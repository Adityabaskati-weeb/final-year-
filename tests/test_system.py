import json
import shutil
import time
import unittest
import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.config import ROOT, Settings
from backend.features import FEATURES, features, connection, binary_label, LogParser, read_log
from backend.detection import Detector
from backend.service import Service
from backend.main import create_app
from backend.zeek import Tail
from backend.database import Store
from backend.firewall import ResponseEngine, WindowsFirewallManager, LinuxFirewallManager
from ml.train import load_manifest
import hashlib


def record():
    # Values from the first official CTU-Honeypot-Capture-4-1 connection.
    return {"ts": 1540469302.538640, "uid": "CGm6jB4dXK71ZDWUDh",
            "id.orig_h": "192.168.1.132", "id.orig_p": 58687,
            "id.resp_h": "216.239.35.4", "id.resp_p": 123,
            "proto": "udp", "service": "-", "duration": .114184,
            "orig_bytes": 48, "resp_bytes": 48, "conn_state": "SF",
            "missed_bytes": 0, "orig_pkts": 1, "orig_ip_bytes": 76,
            "resp_pkts": 1, "resp_ip_bytes": 76, "label": "benign"}


class SystemTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / ".test-work" / str(uuid.uuid4())
        self.root.mkdir(parents=True)

    def tearDown(self):
        if self.root.resolve().is_relative_to((ROOT / ".test-work").resolve()):
            shutil.rmtree(self.root)

    def test_features_exclude_identity_and_labels(self):
        row = record()
        self.assertEqual(list(features(row)), FEATURES)
        self.assertEqual(len(FEATURES), 11)
        self.assertEqual(features(row), features({**row, "label": "malicious", "id.orig_h": "10.0.0.1"}))
        self.assertEqual(connection(row)["extractor"], "zeek-conn-v1")
        self.assertEqual(binary_label(row), "normal")
        with self.assertRaises(ValueError):
            binary_label({"label": "unknown"})

    def test_missing_and_invalid_features(self):
        row = record()
        del row["duration"]
        self.assertIsNone(features(row)["duration"])
        with self.assertRaises(ValueError):
            features({**row, "orig_pkts": float("nan")})
        del row["orig_pkts"]
        with self.assertRaises(ValueError):
            features(row)
        with self.assertRaises(ValueError):
            connection({**record(), "id.resp_p": 70000})

    def test_iot23_packed_label_columns(self):
        parser = LogParser()
        parser.parse("#fields\tts\ttunnel_parents   label   detailed-label\n")
        row = parser.parse("1\t-   Malicious   C&C\n")
        self.assertEqual(row["detailed-label"], "C&C")
        self.assertEqual(binary_label(row), "attack")

    def test_tail_does_not_replay_and_waits_for_complete_line(self):
        path = self.root / "conn.log"
        path.write_text('{"uid":"old"}\n', encoding="utf-8")
        tail = Tail(path)
        self.assertEqual(tail.poll(), [])
        with path.open("a", encoding="utf-8") as stream:
            stream.write('{"uid":"new"}')
        self.assertEqual(tail.poll(), [])
        with path.open("a", encoding="utf-8") as stream:
            stream.write("\n")
        self.assertEqual(tail.poll(), [{"uid": "new"}])
        path.write_text('{}\n', encoding="utf-8")
        self.assertEqual(tail.poll(), [{}])

    def test_live_requires_recent_registered_connection_and_validated_model(self):
        service = Service(Settings(data_dir=self.root))
        try:
            with self.assertRaises(ValueError):
                service.process(record(), "live")
            service.store.put("devices", {"id": "sensor", "origin": "live", "ip": "192.168.1.132"})
            row = {**record(), "ts": time.time() - 1}
            result = service.process(row, "live")
            self.assertEqual(result["prediction"], "unknown")
            self.assertEqual(service.store.rows("alerts"), [])
            self.assertEqual(service.store.rows("blocks"), [])
            self.assertIsNone(service.process(row, "live"))
            with self.assertRaises(ValueError):
                service.process(record(), "demo")
        finally:
            service.store.close()

    def test_lab_alert_test_is_explicit_and_does_not_create_detection(self):
        service = Service(Settings(data_dir=self.root))
        try:
            result = service.trigger_lab_alert(3)
            self.assertEqual(result["status"], "started")
            self.assertTrue(service.lab_alert_until > time.time())
            self.assertEqual(service.store.rows("alerts"), [])
            self.assertEqual(service.store.rows("detections"), [])
        finally:
            service.store.close()

    def test_api_and_no_synthetic_routes(self):
        app = create_app(Settings(data_dir=self.root, admin_token="test"))
        with TestClient(app) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/api/system/status").status_code, 401)
            response = client.get("/api/system/status", headers={"Authorization": "Bearer test"})
            self.assertEqual(response.status_code, 200)
            paths = client.get("/openapi.json").json()["paths"]
            self.assertFalse(any("simulation" in path for path in paths))
            self.assertIn("/api/zeek/flows", paths)
            self.assertEqual(client.post("/api/zeek/flows", json={"records": [record()]}).status_code, 401)

    def test_real_candidate_is_not_live_approved(self):
        path = ROOT / "runtime/iot23-model/model.joblib"
        if not path.exists():
            self.skipTest("Download and train official data for integration test")
        detector = Detector(path)
        self.assertTrue(detector.status()["ready"], detector.error)
        self.assertFalse(detector.status()["response_eligible"])
        self.assertIn(detector.predict(record())["prediction"], {"benign", "malicious"})
        report = json.loads(path.with_name("evaluation.json").read_text())
        self.assertFalse(report["live_validated"])

    def test_manifest_checksum_and_capture_overlap(self):
        path = self.root / "conn.json"
        path.write_text(json.dumps(record()) + "\n", encoding="utf-8")
        entry = dict(path=path.name, capture_id="real-fixture", split="train",
                     provenance="iot23_official", sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps([entry, entry]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Repeated capture"):
            load_manifest(manifest)
        manifest.write_text(json.dumps([{**entry, "sha256": "invalid"}]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "integrity"):
            load_manifest(manifest)

    def test_sensor_auth_replay_and_unknown_status(self):
        app = create_app(Settings(data_dir=self.root, sensor_token="test-sensor"))
        app.state.service.store.put("devices", dict(id="sensor", ip="127.0.0.1", name="test", type="ESP32", origin="live"))
        body = dict(device_id="sensor", sequence=1, device_uptime_ms=1000, temperature_c=30, humidity_percent=50)
        with TestClient(app, client=("127.0.0.1", 40000)) as client:
            self.assertEqual(client.post("/api/telemetry", json=body).status_code, 401)
            response = client.post("/api/telemetry", json=body, headers={"X-IoT-Token": "test-sensor"})
            self.assertEqual(response.status_code, 202)
            self.assertEqual(response.headers["x-iot-security-status"], "UNKNOWN")
            self.assertEqual(client.post("/api/telemetry", json=body, headers={"X-IoT-Token": "test-sensor"}).status_code, 409)

    def test_telemetry_status_automatically_alerts_only_for_validated_malicious_flow(self):
        service = Service(Settings(data_dir=self.root))
        try:
            with patch.object(service.live_model, "status", return_value={"response_eligible": True}):
                service.store.put("traffic", {"origin": "live", "schema": "zeek-conn-v1", "device_id": "sensor",
                                               "prediction": "benign"})
                self.assertEqual(service.telemetry_security_status("sensor"), "NORMAL")
                alert = service.store.put("alerts", {"origin": "live", "schema": "zeek-conn-v1", "device_id": "sensor",
                                                       "prediction": "malicious"})
                signal = service.telemetry_security_signal("sensor")
                self.assertEqual(signal["status"], "SECURITY_ALERT")
                self.assertEqual(signal["alert_id"], alert["id"])
                self.assertEqual(service.telemetry_security_status("sensor"), "SECURITY_ALERT")
            with patch.object(service.live_model, "status", return_value={"response_eligible": False}):
                self.assertEqual(service.telemetry_security_status("sensor"), "UNKNOWN")
        finally:
            service.store.close()

    def test_state_uses_current_session_and_marks_observed_benign_device_normal(self):
        service = Service(Settings(data_dir=self.root))
        try:
            service.store.put("devices", {"id": "sensor", "ip": "192.0.2.10", "name": "test", "type": "ESP32",
                                          "origin": "live", "last_seen": time.time()})
            service.store.put("events", {"run_id": "previous-run", "origin": "live", "schema": "zeek-conn-v1",
                                         "kind": "OLD_EVENT"})
            service.store.put("events", {"run_id": service.run_id, "origin": "live", "schema": "zeek-conn-v1",
                                         "kind": "CURRENT_EVENT"})
            service.store.put("events", {"run_id": "previous-run", "origin": "live", "schema": "zeek-conn-v1",
                                         "kind": "LAB_ALERT_TEST_STARTED", "duration_seconds": 120})
            service.store.put("traffic", {"run_id": service.run_id, "origin": "live", "schema": "zeek-conn-v1",
                                           "device_id": "sensor", "prediction": "benign", "risk_score": 4})
            state = service.state()
            self.assertEqual(state["events"][0]["kind"], "CURRENT_EVENT")
            self.assertEqual(state["devices"][0]["security_status"], "normal")
            self.assertFalse(service.lab_alert_active())
        finally:
            service.store.close()

    def test_firewall_dry_run_protection_and_expiry(self):
        source, target = "10.77.0.55", "10.77.0.22"
        self.assertEqual(len(WindowsFirewallManager().commands(source, True)), 2)
        self.assertEqual(LinuxFirewallManager().commands(source, True)[0][0], "iptables")
        with self.assertRaises(ValueError):
            WindowsFirewallManager().commands("1.2.3.4'; bad", True)
        store = Store(self.root / "firewall.sqlite")
        try:
            engine = ResponseEngine(store, Settings(data_dir=self.root, protected_ips=("10.77.0.1",)),
                                    lambda *a, **k: None, lambda: [target])
            for ip in ("127.0.0.1", "::1", target, "10.77.0.1", "224.0.0.1"):
                with self.assertRaises(ValueError):
                    engine.block(ip, "test")
            protected = engine.record_protected(target, "test", "tcp_connection_probe", "protected lab host")
            self.assertEqual(protected["status"], "protected")
            self.assertFalse(protected["active"])
            row = engine.block(source, "test", "live")
            self.assertEqual(row["status"], "dry_run")
            self.assertFalse(row["verified"])
            self.assertEqual(row["scope"], "host")
            self.assertEqual(row["id"], engine.block(source, "test", "live")["id"])
            store.put("blocks", {**row, "expires_at": 0})
            engine.expire()
            self.assertEqual(store.get("blocks", row["id"])["status"], "released")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
