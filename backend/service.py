import asyncio
import hashlib
import json
import logging
import time
import threading
import uuid
from pathlib import Path
from .database import Store
from .detection import Detector
from .attack_types import classify_live_flow
from .attack_family import AttackFamilyDetector
from .features import connection, read_log, SCHEMA
from .firewall import ResponseEngine
from .zeek import Tail
from .iot_audit_candidate import IoTAuditCandidate
from .packet_capture import ScapyFlowCapture

logger = logging.getLogger("iot.events")
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


class Service:
    def __init__(self, settings):
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(settings.data_dir / "iot.sqlite3")
        self.started, self.run_id = time.time(), str(uuid.uuid4())
        model_path = Path(settings.live_model) if settings.live_model else None
        if model_path is None:
            candidates = sorted(settings.data_dir.glob("iot23-model*/model.joblib"))
            model_path = candidates[-1] if candidates else settings.data_dir / "iot23-model/model.joblib"
        self.live_model = Detector(model_path)
        self.attack_type_model = AttackFamilyDetector(settings.attack_type_model)
        self.iot_audit_model = IoTAuditCandidate(settings.data_dir / "iot-audit-pretrained/binary_lightgbm.joblib")
        self.store.put("models", {"id": "zeek", **self.live_model.status()})
        self.store.put("models", {"id": "attack_type", **self.attack_type_model.status()})
        self.store.put("models", {"id": "iot-audit", **self.iot_audit_model.status()})
        self.response = ResponseEngine(self.store, settings, self.event,
            lambda: [d["ip"] for d in self.devices()], run_id=self.run_id)
        self.suppression, self.seen, self.streaks = {}, {}, {}
        self.process_lock = threading.Lock()
        self.telemetry_lock = threading.Lock()
        self.ingest_busy = False
        self.capture_generation = 0
        self.analysis_task = None
        self.sniffer = None  # Capture lifecycle flag retained for API registration guards.
        self.tail = None
        self.packet_capture = None
        self.capture_error = None
        self.capture_dropped = 0
        self.last_flow_at = None
        self.lab_alert_until = 0
        self.worker_task = None
        self.expiry_task = None

    def credibility(self):
        """Return the last explicit evidence snapshot; never manufacture one."""
        path = self.settings.data_dir / "credibility/report.json"
        if not path.is_file():
            return {
                "status": "not_generated",
                "message": "Run scripts/build_credibility_report.py after collecting evidence.",
            }
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            report["status"] = "available"
            return report
        except (OSError, json.JSONDecodeError) as error:
            return {"status": "invalid", "message": str(error)}

    def trigger_lab_alert(self, seconds=12):
        self.lab_alert_until = max(self.lab_alert_until, time.time() + seconds)
        self.event("LAB_ALERT_TEST_STARTED", origin="live", duration_seconds=seconds)
        return {"status": "started", "duration_seconds": seconds}

    def lab_alert_active(self):
        now = time.time()
        if self.lab_alert_until > now:
            return True
        return any(
            event.get("kind") == "LAB_ALERT_TEST_STARTED"
            and event.get("timestamp", 0) + event.get("duration_seconds", 0) > now
            for event in self.store.rows("events", 50, now - 30)
        )

    async def run_sync(self, function, *args):
        job = asyncio.create_task(asyncio.to_thread(function, *args))
        try:
            return await asyncio.shield(job)
        except asyncio.CancelledError:
            # Finish an in-flight database/OS operation before closing the store.
            await job
            raise

    def devices(self):
        return [d for d in self.store.rows("devices", 10000) if d.get("origin") == "live"]

    def event(self, kind, **data):
        row = self.store.put("events", {**data, "id": str(uuid.uuid4()), "timestamp": time.time(),
                           "kind": kind, "schema": SCHEMA, "run_id": self.run_id})
        logger.info(json.dumps(row))
        return row

    def process(self, raw, origin, capture_id=None):
        with self.process_lock:
            return self._process(raw, origin, capture_id)

    def _process(self, raw, origin, capture_id=None):
        item = connection(raw)
        now = time.time()
        if origin not in {"live", "dataset"}:
            raise ValueError("Synthetic input is not supported")
        if origin == "live" and not -30 <= now - item["ended_at"] <= 120:
            raise ValueError("Historical/future flow rejected from live ingestion")
        key = (origin, capture_id, item["uid"], item["started_at"])
        if key in self.seen:
            return None
        if len(self.seen) >= 20000:
            self.seen = {k: v for k, v in self.seen.items() if v > now - 120}
            if len(self.seen) >= 20000:
                raise ValueError("Live deduplication capacity reached")
        matches = [d for d in self.devices() if d["ip"] in (item["source_ip"], item["destination_ip"])]
        if origin == "live" and not matches:
            raise ValueError("Flow does not involve a registered device")
        self.seen[key] = now
        if origin == "live" and not self.live_model.status()["response_eligible"]:
            result = dict(prediction="unknown", attack_type="unknown", confidence=None,
                          attack_probability=None, risk_score=None,
                          reasons=["Live validation has not passed; candidate model restricted to recorded analysis"])
        else:
            result = self.live_model.predict(item["features"])
            if origin == "live":
                result = classify_live_flow(item, result, self.attack_type_model)
        row = self.store.put("traffic", {**item, **result, "origin": origin, "schema": SCHEMA,
                  "model_sha256": self.live_model.model_sha256 if result["prediction"] != "unknown" else None,
                  "run_id": self.run_id, "capture_id": capture_id,
                  "device_id": matches[0]["id"] if matches and origin == "live" else None,
                  "ground_truth": raw.get("label") if origin == "dataset" else None})
        if origin == "live":
            self.last_flow_at = now
        if result["prediction"] == "malicious":
            self.store.put("detections", row)
            alert_key = (origin, item["source_ip"], item["destination_ip"])
            if now - self.suppression.get(alert_key, 0) >= 30:
                self.store.put("alerts", row)
                self.event("ATTACK_DETECTED", **row)
                self.suppression[alert_key] = now
            # Dataset rows can never affect hardware or the OS firewall.
            if origin == "live" and self.live_model.status()["response_eligible"]:
                inbound = any(d["ip"] == item["destination_ip"] for d in matches)
                qualifies = result["confidence"] >= self.settings.block_threshold and result["risk_score"] >= self.settings.block_risk
                count, last = self.streaks.get(alert_key, (0, 0))
                count = count + 1 if now - last <= 30 else 1
                self.streaks[alert_key] = (count if qualifies else 0, now)
                if inbound and qualifies and count >= 2:
                    try:
                        self.response.block(item["source_ip"], "; ".join(result["reasons"]), "live", result["attack_type"])
                    except ValueError as error:
                        self.response.record_protected(
                            item["source_ip"],
                            "; ".join(result["reasons"]),
                            result["attack_type"],
                            str(error),
                        )
        if len(self.suppression) > 5000:
            self.suppression = {k: v for k, v in self.suppression.items() if v > now - 30}
        return row

    def captures(self):
        manifest = self.settings.data_dir / "iot23/manifest.json"
        if not manifest.exists():
            return []
        return json.loads(manifest.read_text(encoding="utf-8"))

    async def analyze(self, capture_id):
        try:
            entry = next((c for c in self.captures() if c["capture_id"] == capture_id), None)
            if not entry:
                raise ValueError("Unknown downloaded capture")
            path = (self.settings.data_dir / "iot23" / entry["path"]).resolve()
            if not path.is_relative_to((self.settings.data_dir / "iot23").resolve()):
                raise ValueError("Invalid capture path")
            with path.open("rb") as file:
                if hashlib.file_digest(file, "sha256").hexdigest() != entry["sha256"]:
                    raise ValueError("Dataset hash mismatch")
            self.event("RECORDED_ANALYSIS_STARTED", origin="dataset", capture_id=capture_id)
            for index, raw in enumerate(read_log(path)):
                if index >= 500:
                    break
                await self.run_sync(self.process, raw, "dataset", capture_id)
                await asyncio.sleep(.02)
        except Exception as error:
            self.event("RECORDED_ANALYSIS_FAILED", origin="dataset", reason=str(error))
        finally:
            self.event("RECORDED_ANALYSIS_STOPPED", origin="dataset", capture_id=capture_id)

    def start_analysis(self, capture_id):
        if not self.live_model.bundle:
            raise ValueError("Train the real-data model first")
        if self.analysis_task and not self.analysis_task.done():
            raise ValueError("Recorded analysis already running")
        if capture_id not in {e["capture_id"] for e in self.captures()}:
            raise ValueError("Unknown downloaded capture")
        self.seen = {k: v for k, v in self.seen.items() if k[0] == "live"}
        self.analysis_task = asyncio.create_task(self.analyze(capture_id))

    async def stop_analysis(self):
        if self.analysis_task and not self.analysis_task.done():
            self.analysis_task.cancel()
            try:
                await self.analysis_task
            except asyncio.CancelledError:
                pass

    def interfaces(self):
        options = []
        if self.settings.scapy_interface:
            options.append({"id": "scapy-live", "name": f"Live Npcap: {self.settings.scapy_interface}"})
        if self.settings.zeek_log:
            options.append({"id": "zeek-log", "name": "Local Zeek JSON conn.log"})
        if self.settings.zeek_token:
            options.append({"id": "zeek-agent", "name": "Authenticated Zeek collector"})
        return options

    async def start_capture(self, interface):
        if self.sniffer:
            raise ValueError("Monitoring already running")
        if not self.devices():
            raise ValueError("Register your physical device first")
        if interface not in {i["id"] for i in self.interfaces()}:
            raise ValueError("Configure SCAPY_CAPTURE_INTERFACE, ZEEK_LOG_PATH or ZEEK_INGEST_TOKEN")
        extractor = "scapy-lab-flow-v1" if interface == "scapy-live" else "zeek-conn-v1"
        if not self.live_model.compatible_extractor(extractor):
            raise ValueError(
                f"Selected capture source uses {extractor}, but the loaded model was not trained and validated with it"
            )
        if interface == "scapy-live":
            capture = ScapyFlowCapture(self.settings.scapy_interface,
                                       {d["ip"] for d in self.devices()})
            capture.start()
            self.packet_capture = capture
        self.tail = Tail(self.settings.zeek_log) if interface == "zeek-log" else None
        self.capture_generation += 1
        self.sniffer = interface
        self.capture_error = None
        self.event("ZEEK_MONITORING_STARTED", origin="live", interface=interface)

    async def stop_capture(self):
        self.capture_generation += 1
        capture, self.packet_capture = self.packet_capture, None
        if capture:
            capture.stop()
        self.sniffer, self.tail = None, None

    async def worker(self):
        while True:
            try:
                if self.tail:
                    for raw in self.tail.poll():
                        try:
                            await self.run_sync(self.process, raw, "live")
                        except (ValueError, KeyError, TypeError) as error:
                            self.capture_dropped += 1
                            self.capture_error = str(error)
                if self.packet_capture:
                    self.capture_error = self.packet_capture.error
                    for raw in self.packet_capture.poll():
                        try:
                            await self.run_sync(self.process, raw, "live")
                        except (ValueError, KeyError, TypeError) as error:
                            self.capture_dropped += 1
                            self.capture_error = str(error)
            except Exception as error:
                self.capture_error = str(error)
                self.event("COLLECTOR_ERROR", origin="live", reason=str(error))
                await self.stop_capture()
            await asyncio.sleep(.25)

    async def expire_worker(self):
        while True:
            try:
                await self.run_sync(self.response.expire)
            except Exception as error:
                self.event("RESPONSE_EXPIRY_FAILED", origin="live", reason=str(error))
            await asyncio.sleep(1)

    def state(self):
        devices = self.devices()
        recent = [r for r in self.store.rows("traffic", 1000, time.time() - 30) if r.get("schema") == SCHEMA and r["origin"] == "live"]
        for device in devices:
            device["status"] = "online" if time.time() - device.get("last_seen", 0) < 30 else "device_offline"
            observed = [r for r in recent if r.get("device_id") == device["id"]]
            device["current_risk"] = max((r["risk_score"] for r in observed if r["risk_score"] is not None), default=None)
            device["security_status"] = "at_risk" if any(r["prediction"] == "malicious" for r in observed) else "unknown"
        return dict(run_id=self.run_id, uptime=int(time.time() - self.started), devices=devices,
            firewall_mode=self.settings.firewall_mode, monitoring=bool(self.sniffer),
            capture_error=self.capture_error, capture_dropped=self.capture_dropped, last_flow_at=self.last_flow_at,
            capture_source=self.packet_capture.status() if self.packet_capture else None,
            analysis=bool(self.analysis_task and not self.analysis_task.done()),
            captures=self.captures(), models={"zeek": self.live_model.status(),
                                               "attack_type": self.attack_type_model.status(),
                                               "iot_audit": self.iot_audit_model.status()},
            credibility=self.credibility(),
            lab_alert_test=self.lab_alert_active(),
            **{table: [r for r in self.store.rows(table, 1000, self.started if table in {"traffic", "detections", "alerts"} else 0)
                       if r.get("schema") == SCHEMA or table in {"blocks", "readings"} and r.get("origin") == "live"][:200]
               for table in ("traffic", "detections", "alerts", "blocks", "events", "readings")})
