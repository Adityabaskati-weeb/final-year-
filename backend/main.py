import asyncio
from contextlib import asynccontextmanager
import hmac
import ipaddress
import os
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, Depends, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field, ConfigDict, field_validator
from .config import Settings, ROOT
from .service import Service


class Device(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    name: str = Field(min_length=1, max_length=80)
    ip: str
    type: str = Field(default="ESP32", max_length=40)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ipaddress.ip_address(value))


class Reading(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    device_id: str = Field(max_length=64)
    sequence: int = Field(ge=0)
    device_uptime_ms: int = Field(ge=0)
    boot_id: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{32}$")
    temperature_c: float = Field(ge=-40, le=100)
    humidity_percent: float = Field(ge=0, le=100)


class Block(BaseModel):
    ip: str
    reason: str = Field(min_length=1, max_length=500)
    origin: str = Field(default="live", pattern=r"^live$")


class Release(BaseModel):
    id: str


class Analysis(BaseModel):
    capture_id: str


class FlowBatch(BaseModel):
    records: list[dict] = Field(min_length=1, max_length=100)


class Capture(BaseModel):
    interface: str


class LabAlertTest(BaseModel):
    seconds: int = Field(default=12, ge=3, le=30)


def create_app(settings=None):
    settings = settings or Settings.from_env()
    service = Service(settings)

    @asynccontextmanager
    async def lifespan(app):
        service.worker_task = asyncio.create_task(service.worker())
        service.expiry_task = asyncio.create_task(service.expire_worker())
        try:
            yield
        finally:
            await service.stop_analysis()
            await service.stop_capture()
            service.worker_task.cancel()
            service.expiry_task.cancel()
            try:
                await service.worker_task
            except asyncio.CancelledError:
                pass
            try:
                await service.expiry_task
            except asyncio.CancelledError:
                pass
            # Best effort: only this application's rules are removed.
            for row in service.store.rows("blocks", 100000):
                if row.get("active") and row["status"] != "released":
                    service.response.unblock(row["id"])
            service.store.close()

    app = FastAPI(title="Updated IoT IDS", lifespan=lifespan)
    app.state.service = service
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver", *settings.trusted_hosts, *service.response.protected])
    app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:5175", "http://localhost:5175"],
                       allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])

    def authorized(host, token):
        if settings.admin_token:
            return hmac.compare_digest(token, settings.admin_token)
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    def auth(request: Request):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).hostname not in {request.url.hostname, "localhost", "127.0.0.1"}:
            raise HTTPException(403, "Untrusted browser origin")
        if not authorized(request.client.host, request.headers.get("authorization", "").removeprefix("Bearer ")):
            raise HTTPException(401, "Local access or ADMIN_TOKEN required")

    @app.exception_handler(ValueError)
    async def value_error(request, error):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": str(error)}, status_code=400)

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "updated-iot-work"}

    @app.get("/api/system/status", dependencies=[Depends(auth)])
    def state():
        return service.state()

    @app.get("/api/interfaces", dependencies=[Depends(auth)])
    def interfaces():
        return service.interfaces()

    @app.get("/api/models", dependencies=[Depends(auth)])
    def models():
        return service.state()["models"]

    @app.get("/api/credibility", dependencies=[Depends(auth)])
    def credibility():
        return service.credibility()

    @app.get("/api/devices", dependencies=[Depends(auth)])
    def devices():
        return service.state()["devices"]

    @app.post("/api/devices", dependencies=[Depends(auth)])
    def register(device: Device):
        if service.sniffer:
            raise ValueError("Stop capture before changing devices")
        if device.id == "demo-sensor":
            raise ValueError("Reserved demo device ID")
        if any(d["ip"] == device.ip and d["id"] != device.id for d in service.store.rows("devices", 10000)):
            raise ValueError("IP already registered")
        if len(service.store.rows("devices", 10000)) >= 100 and not service.store.get("devices", device.id):
            raise ValueError("Device registry is full")
        for block in service.store.rows("blocks", 100000):
            if block["source_ip"] == device.ip and block["status"] != "released":
                raise ValueError("Unblock this IP before registering it")
        row = service.store.put("devices", {**device.model_dump(), "origin": "live", "last_seen": 0})
        service.event("DEVICE_REGISTERED", device_id=device.id, ip=device.ip)
        return row

    @app.post("/api/telemetry", status_code=202)
    def telemetry(reading: Reading, request: Request, response: Response):
        import time
        if not settings.sensor_token or not hmac.compare_digest(request.headers.get("x-iot-token", ""), settings.sensor_token):
            raise HTTPException(401, "Sensor token required")
        with service.telemetry_lock:
            device = service.store.get("devices", reading.device_id)
            if not device or device.get("origin") != "live" or device["ip"] != request.client.host:
                raise HTTPException(403, "Register device ID and source IP first")
            previous = device.get("sequence", -1)
            uptime = device.get("device_uptime_ms", 0)
            retired = device.get("retired_boot_ids", [])
            current_boot = device.get("boot_id")
            if reading.boot_id in retired:
                raise HTTPException(409, "Retired sensor boot session")
            if reading.boot_id is None or reading.boot_id == current_boot:
                if reading.sequence <= previous or reading.device_uptime_ms < uptime:
                    raise HTTPException(409, "Repeated/out-of-order telemetry; legacy firmware reboot requires re-registration")
            elif current_boot:
                if reading.device_uptime_ms >= uptime or len(retired) >= 1024:
                    raise HTTPException(409, "Unconfirmed boot transition; re-register device")
                retired = [*retired, current_boot]
            first = time.time() - device.get("last_seen", 0) >= 30
            service.store.put("devices", {**device, "last_seen": time.time(), "sequence": reading.sequence,
                                          "device_uptime_ms": reading.device_uptime_ms,
                                          "boot_id": reading.boot_id, "retired_boot_ids": retired})
            service.store.put("readings", {**reading.model_dump(), "origin": "live"})
        if first:
            service.event("SENSOR_CONNECTED", device_id=device["id"], origin="live")
        lab_test = service.lab_alert_active()
        status = "LAB_TEST_ALERT" if lab_test else service.telemetry_security_status(device["id"])
        response.headers["X-IoT-Security-Status"] = status
        return {"device_id": device["id"], "status": status}

    def collection_endpoint(table):
        def get_rows(limit: int = 200):
            return service.state()[table][:max(1, min(limit, 200))]
        return get_rows

    for path, table in (("traffic", "traffic"), ("alerts", "alerts"), ("detections", "detections"),
                        ("blocklist", "blocks"), ("history", "events"), ("readings", "readings")):
        app.add_api_route("/api/" + path, collection_endpoint(table), methods=["GET"], dependencies=[Depends(auth)])

    @app.post("/api/firewall/block", dependencies=[Depends(auth)])
    def block(body: Block):
        return service.response.block(body.ip, body.reason, body.origin)

    @app.post("/api/firewall/unblock", dependencies=[Depends(auth)])
    def unblock(body: Release):
        return service.response.unblock(body.id)

    @app.get("/api/captures", dependencies=[Depends(auth)])
    def captures():
        return service.captures()

    @app.post("/api/analysis/start", dependencies=[Depends(auth)])
    async def start_analysis(body: Analysis):
        service.start_analysis(body.capture_id)
        return {"status": "started", "origin": "dataset"}

    @app.post("/api/analysis/stop", dependencies=[Depends(auth)])
    async def stop_analysis():
        await service.stop_analysis()
        return {"status": "stopped"}

    @app.post("/api/zeek/flows")
    async def ingest(body: FlowBatch, request: Request):
        if not settings.zeek_token or not hmac.compare_digest(settings.zeek_token, request.headers.get("x-zeek-token", "")):
            raise HTTPException(401, "Collector token required")
        if service.sniffer != "zeek-agent":
            raise HTTPException(409, "Start Zeek collector monitoring first")
        if service.ingest_busy:
            service.capture_dropped += len(body.records)
            raise HTTPException(429, "Collector busy; retry this batch", headers={"Retry-After": "1"})
        service.ingest_busy = True
        generation = service.capture_generation
        accepted, rejected = 0, 0
        try:
            for raw in body.records:
                if service.sniffer != "zeek-agent" or service.capture_generation != generation:
                    rejected += len(body.records) - accepted - rejected
                    service.capture_dropped += len(body.records) - accepted - rejected
                    break
                try:
                    if await service.run_sync(service.process, raw, "live"):
                        accepted += 1
                except (ValueError, KeyError, TypeError):
                    rejected += 1
                    service.capture_dropped += 1
        finally:
            service.ingest_busy = False
        return {"accepted": accepted, "rejected": rejected}

    @app.post("/api/monitoring/start", dependencies=[Depends(auth)])
    async def start_capture(body: Capture):
        await service.start_capture(body.interface)
        return {"status": "started"}

    @app.post("/api/monitoring/stop", dependencies=[Depends(auth)])
    async def stop_capture():
        await service.stop_capture()
        return {"status": "stopped"}

    @app.post("/api/lab/alert-test", dependencies=[Depends(auth)])
    def lab_alert_test(body: LabAlertTest):
        return service.trigger_lab_alert(body.seconds)

    @app.websocket("/ws/events")
    async def events(websocket: WebSocket):
        origin = websocket.headers.get("origin")
        if origin and urlparse(origin).hostname not in {websocket.url.hostname, "127.0.0.1", "localhost"}:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        try:
            token = await asyncio.wait_for(websocket.receive_json(), timeout=5)
            if not authorized(websocket.client.host, str(token.get("token", ""))):
                await websocket.close(code=1008)
                return
            while True:
                await websocket.send_json(service.state())
                await asyncio.sleep(1)
        except (WebSocketDisconnect, asyncio.TimeoutError, RuntimeError):
            pass

    dist = ROOT / "frontend/dist"
    if dist.is_dir():
        app.mount("/", StaticFiles(directory=dist, html=True), name="dashboard")
    return app
