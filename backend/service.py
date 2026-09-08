import asyncio
import json
import logging
import queue
import time
import uuid
from .database import Store
from .detection import Detector
from .features import Packet, Windows
from .firewall import ResponseEngine
from .simulation import packets, SOURCE, TARGET, SCENARIOS

logger = logging.getLogger("iot.events")
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)


class Service:
    def __init__(self, settings):
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(settings.data_dir / "iot.sqlite3")
        self.started = time.time()
        self.run_id = str(uuid.uuid4())
        self.demo_model = Detector(settings.data_dir / "demo-model/model.joblib", "synthetic_demo")
        self.live_model = Detector(settings.live_model, "real_capture")
        for name, model in (("demo", self.demo_model), ("live", self.live_model)):
            self.store.put("models", {"id": name, **model.status()})
        self.response = ResponseEngine(self.store, settings, self.event,
            lambda: [d["ip"] for d in self.store.rows("devices", 10000)])
        self.streaks, self.suppression = {}, {}
        self.demo_task = None
        self.sniffer = None
        self.interface = None
        self.capture_error = None
        self.buffer = queue.Queue(maxsize=2048)
        self.extractor = Windows()
        self.capture_dropped = 0
        self.worker_task = None

    def event(self, kind, **data):
        row = self.store.put("events", {**data, "id": str(uuid.uuid4()), "timestamp": time.time(),
                                        "kind": kind, "run_id": self.run_id})
        logger.info(json.dumps(row))
        return row

    def process(self, window, origin):
        if len(self.streaks) > 8192:
            self.streaks = {key: value for key, value in self.streaks.items() if value[1] >= window["window_start"] - 10}
        if len(self.suppression) > 8192:
            cutoff = time.time() - 30
            self.suppression = {key: value for key, value in self.suppression.items() if value >= cutoff}
        detector = self.demo_model if origin == "demo" else self.live_model
        result = detector.predict(window["features"], self.settings.detection_threshold)
        device = next((d for d in self.store.rows("devices", 10000) if d["ip"] == window["destination_ip"]), None)
        row = self.store.put("traffic", {**window, **result, "origin": origin, "run_id": self.run_id,
                                         "device_id": device["id"] if device else None})
        key = (origin, row["source_ip"], row["destination_ip"])
        prior_count, prior_time = self.streaks.get(key, (0, -100))
        if result["prediction"] != "malicious":
            self.streaks[key] = (0, window["window_start"])
            return row
        self.store.put("detections", row)
        now = time.time()
        if now - self.suppression.get(key, 0) >= 30:
            self.store.put("alerts", row)
            self.event("ATTACK_DETECTED", **row)
            self.suppression[key] = now
        qualifies = result["confidence"] >= self.settings.block_threshold and result["risk_score"] >= self.settings.block_risk
        count = prior_count + 1 if window["window_start"] - prior_time == 5 else 1
        self.streaks[key] = (count if qualifies else 0, window["window_start"])
        if qualifies and count >= 2:
            try:
                self.response.block(row["source_ip"], "; ".join(result["reasons"]), origin, result["attack_type"])
            except ValueError as error:
                self.event("RESPONSE_PROTECTED", source_ip=row["source_ip"], reason=str(error), origin=origin)
        return row

    async def demo(self, scenario):
        self.store.put("devices", dict(id="demo-sensor", name="Virtual temperature sensor", ip=TARGET,
                       type="Synthetic", origin="demo", last_seen=time.time()))
        old = self.store.get("blocks", "demo:" + SOURCE)
        if old:
            self.response.unblock(old["id"])
        self.streaks = {k: v for k, v in self.streaks.items() if k[0] != "demo"}
        self.suppression = {k: v for k, v in self.suppression.items() if k[0] != "demo"}
        self.event("SENSOR_CONNECTED", device_id="demo-sensor", origin="demo")
        extractor = Windows()
        start = int(time.time() // 5) * 5
        try:
            for index in range(10):
                pattern = "normal" if index < 3 else scenario
                if index == 3:
                    self.event("ATTACK_STARTED", origin="demo", scenario=scenario)
                device = self.store.get("devices", "demo-sensor")
                self.store.put("devices", {**device, "last_seen": time.time()})
                self.store.put("readings", dict(device_id="demo-sensor", temperature=28 + index / 10,
                               humidity=55, origin="demo"))
                rejected = 0
                for packet in packets(pattern, start + index * 5, 91000 + index):
                    if self.response.denied_demo(packet.source):
                        rejected += 1
                    else:
                        for row in extractor.push(packet):
                            self.process(row, "demo")
                for row in extractor.flush(start + (index + 1) * 5):
                    self.process(row, "demo")
                if rejected:
                    self.event("SIMULATED_TRAFFIC_REJECTED", source_ip=SOURCE, packets=rejected, origin="demo")
                await asyncio.sleep(1)
        finally:
            self.event("DEMO_STOPPED", origin="demo")

    def start_demo(self, scenario):
        if scenario not in SCENARIOS:
            raise ValueError("Unknown scenario")
        if self.demo_task and not self.demo_task.done():
            raise ValueError("Demo already running")
        if not self.demo_model.bundle:
            raise ValueError("Train demo model first: python -m ml.train --demo")
        self.demo_task = asyncio.create_task(self.demo(scenario))

    async def stop_demo(self):
        if self.demo_task and not self.demo_task.done():
            self.demo_task.cancel()
            try:
                await self.demo_task
            except asyncio.CancelledError:
                pass

    @staticmethod
    def interfaces():
        from scapy.all import conf
        return [{"id": item.network_name, "name": item.description or item.name} for item in conf.ifaces.values()]

    def enqueue(self, raw):
        packet = Packet.from_scapy(raw)
        if packet:
            try:
                self.buffer.put_nowait(packet)
            except queue.Full:
                self.capture_dropped += 1

    async def start_capture(self, interface):
        if self.sniffer:
            raise ValueError("Capture already running")
        if interface not in {i["id"] for i in self.interfaces()}:
            raise ValueError("Unknown capture interface")
        targets = [d["ip"] for d in self.store.rows("devices", 10000) if d.get("origin") != "demo"]
        if not targets:
            raise ValueError("Register a physical device first")
        from scapy.all import AsyncSniffer
        self.extractor = Windows()
        self.capture_error = None
        self.interface = interface
        self.sniffer = AsyncSniffer(iface=interface, store=False, prn=self.enqueue,
                                   filter=" or ".join("dst host " + ip for ip in targets))
        self.sniffer.start()
        await asyncio.sleep(0.3)
        if getattr(self.sniffer, "exception", None) or not self.sniffer.running:
            self.capture_error = str(getattr(self.sniffer, "exception", "Capture failed"))
            self.sniffer = None
            raise ValueError(self.capture_error)
        self.event("CAPTURE_STARTED", interface=interface, origin="live")

    async def stop_capture(self):
        if self.sniffer:
            sniffer, self.sniffer = self.sniffer, None
            if sniffer.running:
                await asyncio.to_thread(sniffer.stop)
            self.event("CAPTURE_STOPPED", origin="live")
        while not self.buffer.empty():
            self.buffer.get_nowait()
        self.extractor = Windows()

    async def worker(self):
        while True:
            if self.sniffer:
                if getattr(self.sniffer, "exception", None):
                    self.capture_error = str(self.sniffer.exception)
                    await self.stop_capture()
                else:
                    for _ in range(2048):
                        try:
                            packet = self.buffer.get_nowait()
                        except queue.Empty:
                            break
                        for row in self.extractor.push(packet):
                            self.process(row, "live")
                    if self.buffer.empty():
                        for row in self.extractor.flush(time.time()):
                            self.process(row, "live")
            self.response.expire()
            await asyncio.sleep(0.25)

    def state(self):
        devices = self.store.rows("devices", 10000)
        recent = self.store.rows("traffic", 1000, time.time() - 30)
        for device in devices:
            device["status"] = "online" if time.time() - device.get("last_seen", 0) < 30 else "stale"
            observations = [r for r in recent if r.get("device_id") == device["id"] and r["origin"] == device["origin"]]
            device["current_risk"] = max((r["risk_score"] for r in observations if r["prediction"] != "unknown"), default=None)
            device["security_status"] = "at_risk" if any(r["prediction"] == "malicious" for r in observations) else "observed_benign" if observations and all(r["prediction"] == "benign" for r in observations) else "unknown"
        return dict(run_id=self.run_id, uptime=int(time.time() - self.started), devices=devices,
            firewall_mode=self.settings.firewall_mode, monitoring=bool(self.sniffer and self.sniffer.running),
            capture_error=self.capture_error, capture_dropped=self.capture_dropped + self.extractor.dropped,
            simulation=bool(self.demo_task and not self.demo_task.done()),
            models={"demo": self.demo_model.status(), "live": self.live_model.status()},
            **{table: self.store.rows(table, 200, self.started if table in {"traffic", "detections", "alerts"} else 0)
               for table in ("traffic", "detections", "alerts", "blocks", "events", "readings")})
