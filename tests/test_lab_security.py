"""Isolated unit fixtures only; never exported as experiment evidence."""
import shutil
import unittest
import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.config import ROOT, Settings
from backend.lab import authorized_target
from backend.main import create_app
from backend.detection import Detector
from backend.attack_family import AttackFamilyDetector
from backend.attack_types import classify_live_flow
from scripts.zeek_from_pcap import convert


class LabTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / ".test-work" / str(uuid.uuid4())
        self.root.mkdir(parents=True)

    def tearDown(self):
        if self.root.resolve().is_relative_to((ROOT / ".test-work").resolve()):
            shutil.rmtree(self.root)

    def test_only_explicit_private_lab_target(self):
        path = self.root / "lab.yaml"
        path.write_text("targets:\n  - device_id: unit-test\n    ip: 192.168.50.2\n", encoding="utf-8")
        self.assertEqual(authorized_target(path, "192.168.50.2"), "192.168.50.2")
        for target in ("8.8.8.8", "127.0.0.1", "192.168.50.3", "192.0.2.1"):
            with self.assertRaises(ValueError):
                authorized_target(path, target)

    def test_missing_zeek_does_not_fabricate_output(self):
        with patch("scripts.zeek_from_pcap.shutil.which", return_value=None):
            with self.assertRaisesRegex(ValueError, "actual Zeek"):
                convert(self.root / "missing.pcap", self.root / "out")
        self.assertFalse((self.root / "out").exists())

    def test_retired_boot_cannot_refresh_sensor(self):
        app = create_app(Settings(data_dir=self.root, sensor_token="test"))
        service = app.state.service
        service.store.put("devices", dict(id="sensor", ip="127.0.0.1", origin="live"))
        body = dict(device_id="sensor", sequence=10, device_uptime_ms=10000, temperature_c=30,
                    humidity_percent=50, boot_id="a" * 32)
        headers = {"X-IoT-Token": "test"}
        with TestClient(app, client=("127.0.0.1", 40000)) as client:
            self.assertEqual(client.post("/api/telemetry", json=body, headers=headers).status_code, 202)
            reboot = {**body, "sequence": 0, "device_uptime_ms": 50, "boot_id": "b" * 32}
            self.assertEqual(client.post("/api/telemetry", json=reboot, headers=headers).status_code, 202)
            self.assertEqual(client.post("/api/telemetry", json=body, headers=headers).status_code, 409)
            self.assertEqual(client.post("/api/telemetry", json={**reboot, "device_uptime_ms": 10}, headers=headers).status_code, 409)

    def test_collector_backpressure(self):
        app = create_app(Settings(data_dir=self.root, zeek_token="collector"))
        with TestClient(app) as client:
            app.state.service.sniffer = "zeek-agent"
            app.state.service.ingest_busy = True
            response = client.post("/api/zeek/flows", json={"records": [{}]}, headers={"X-Zeek-Token": "collector"})
            self.assertEqual(response.status_code, 429)
            self.assertEqual(app.state.service.capture_dropped, 1)

    def test_stopping_capture_invalidates_collector_batch(self):
        app = create_app(Settings(data_dir=self.root, zeek_token="collector"))
        service = app.state.service
        try:
            service.sniffer = "zeek-agent"
            generation = service.capture_generation
            import asyncio
            asyncio.run(service.stop_capture())
            self.assertNotEqual(generation, service.capture_generation)
            self.assertIsNone(service.sniffer)
        finally:
            service.store.close()

    def test_string_model_flags_rejected(self):
        import joblib
        path = ROOT / "runtime/iot23-model/model.joblib"
        if not path.exists():
            self.skipTest("Real candidate not installed")
        bundle = joblib.load(path)
        bundle["report"] = {**bundle["report"], "eligible": "false"}
        output = self.root / "invalid.joblib"
        joblib.dump(bundle, output)
        self.assertFalse(Detector(output).status()["ready"])

    def test_controlled_tcp_probe_gets_lab_attribution_only(self):
        result = classify_live_flow(
            {"protocol": "tcp", "destination_port": 80},
            {"prediction": "malicious", "attack_type": "unspecified", "reasons": ["binary"]},
        )
        self.assertEqual(result["attack_type"], "tcp_connection_probe")
        self.assertEqual(result["classification_source"], "lab_attribution")

        other = classify_live_flow(
            {"protocol": "udp", "destination_port": 53},
            {"prediction": "malicious", "attack_type": "unspecified", "reasons": ["binary"]},
        )
        self.assertEqual(other["attack_type"], "unknown_attack_pattern")
        self.assertEqual(other["classification_source"], "binary_only")

    def test_attack_family_model_is_disabled_without_promotion(self):
        detector = AttackFamilyDetector(self.root / "missing-family-model.joblib")
        self.assertFalse(detector.status()["ready"])
        self.assertFalse(detector.status()["response_eligible"])
