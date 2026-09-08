import shutil
import unittest
import uuid
from unittest.mock import patch
from fastapi.testclient import TestClient
from backend.config import ROOT, Settings
from backend.database import Store
from backend.features import Windows, vector, FEATURES, Packet
from backend.simulation import packets, dataset, SOURCE, TARGET
from backend.detection import Detector
from backend.firewall import ResponseEngine, WindowsFirewallManager, LinuxFirewallManager
from backend.main import create_app
from ml.train import train


class SystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = ROOT / ".test-work" / str(uuid.uuid4())
        cls.root.mkdir(parents=True)
        cls.report = train(dataset(), cls.root / "demo-model", "synthetic_demo")

    @classmethod
    def tearDownClass(cls):
        if cls.root.resolve().is_relative_to((ROOT / ".test-work").resolve()):
            shutil.rmtree(cls.root)

    def settings(self):
        root = self.root / str(uuid.uuid4())
        root.mkdir()
        shutil.copytree(self.root / "demo-model", root / "demo-model")
        return Settings(data_dir=root, protected_ips=("10.77.0.1",), sensor_token="test-sensor")

    def window(self, scenario, start=100):
        extractor = Windows()
        for packet in packets(scenario, start, 8888):
            extractor.push(packet)
        return extractor.flush(start + 5)[0]

    def test_features_and_order(self):
        row = self.window("normal")
        self.assertEqual(len(vector(row["features"])), 13)
        self.assertEqual(vector(dict(reversed(list(row["features"].items())))), vector(row["features"]))
        self.assertEqual(row["source_ip"], SOURCE)
        with self.assertRaises(ValueError):
            vector({**row["features"], "label": 1})
        with self.assertRaises(ValueError):
            vector({**row["features"], FEATURES[0]: float("nan")})

    def test_scapy_parity(self):
        from scapy.all import IP, TCP
        raw = IP(src=SOURCE, dst=TARGET)/TCP(sport=4567, dport=80, flags="S")
        raw.time = 100
        packet = Packet.from_scapy(raw)
        self.assertEqual(packet.source, SOURCE)
        self.assertEqual(packet.flags, 2)

    def test_inference_provenance(self):
        detector = Detector(self.root / "demo-model/model.joblib", "synthetic_demo")
        self.assertEqual(detector.predict(self.window("normal")["features"], .8)["prediction"], "benign")
        self.assertEqual(detector.predict(self.window("port_scan")["features"], .8)["prediction"], "malicious")
        self.assertFalse(Detector(self.root / "demo-model/model.joblib", "real_capture").bundle)
        self.assertEqual(Detector(None, "real_capture").predict(self.window("normal")["features"], .8)["prediction"], "unknown")

    def test_leakage_rejected(self):
        rows = dataset()
        rows[-1]["session"] = rows[0]["session"]
        with self.assertRaisesRegex(ValueError, "leakage"):
            train(rows, self.root / "invalid", "synthetic_demo")

    def test_threshold_validation(self):
        with self.assertRaises(ValueError):
            Settings(detection_threshold=.95, block_threshold=.8)
        with self.assertRaises(ValueError):
            Settings(firewall_mode="active")
        with self.assertRaises(ValueError):
            Settings(block_seconds=0)

    def test_window_gap_resets_response(self):
        app = create_app(self.settings())
        with TestClient(app, client=("127.0.0.1",40000)):
            service = app.state.service
            service.process(self.window("port_scan",100),"demo")
            service.process(self.window("port_scan",115),"demo")
            self.assertFalse(service.response.denied_demo(SOURCE))
            service.process(self.window("port_scan",120),"demo")
            self.assertTrue(service.response.denied_demo(SOURCE))

    def test_all_simulator_patterns(self):
        detector = Detector(self.root / "demo-model/model.joblib", "synthetic_demo")
        for scenario in ("port_scan","connection_flood","udp_burst","connection_retry"):
            result = detector.predict(self.window(scenario)["features"],.8)
            self.assertEqual(result["attack_type"],scenario)
        with self.assertRaises(ValueError):
            list(packets("unknown",100,1))

    def test_mock_capture_lifecycle(self):
        class Sniffer:
            running = False
            exception = None
            def __init__(self, **kwargs):
                self.kwargs = kwargs
            def start(self):
                self.running = True
            def stop(self):
                self.running = False
        app = create_app(self.settings())
        with TestClient(app,client=("127.0.0.1",40000)) as client:
            client.post("/api/devices",json={"id":"lab","name":"Lab","ip":TARGET})
            with patch("backend.service.Service.interfaces",return_value=[{"id":"test","name":"test"}]), patch("scapy.all.AsyncSniffer",Sniffer):
                self.assertEqual(client.post("/api/monitoring/start",json={"interface":"test"}).status_code,200)
                self.assertEqual(client.post("/api/monitoring/start",json={"interface":"test"}).status_code,400)
                self.assertEqual(client.post("/api/monitoring/stop",json={}).status_code,200)
            self.assertFalse(app.state.service.sniffer)

    def test_firewall_commands_and_protection(self):
        self.assertEqual(len(WindowsFirewallManager().commands(SOURCE, True)), 2)
        self.assertEqual(LinuxFirewallManager().commands(SOURCE, True)[0][0], "iptables")
        self.assertEqual(LinuxFirewallManager().commands("2001:db8::55", True)[0][0], "ip6tables")
        with self.assertRaises(ValueError):
            WindowsFirewallManager().commands("1.2.3.4'; bad", True)
        settings = self.settings()
        store = Store(settings.data_dir / "test.sqlite")
        engine = ResponseEngine(store, settings, lambda *a, **k: None, lambda: [TARGET])
        for ip in ("127.0.0.1", "::1", TARGET, "10.77.0.1", "224.0.0.1"):
            with self.assertRaises(ValueError):
                engine.block(ip, "test")
        one = engine.block(SOURCE, "test", "demo")
        self.assertEqual(one["id"], engine.block(SOURCE, "test", "demo")["id"])
        self.assertTrue(engine.denied_demo(SOURCE))
        engine.unblock(one["id"])
        self.assertFalse(engine.denied_demo(SOURCE))
        row = engine.block(SOURCE, "expiry", "demo")
        store.put("blocks", {**row, "expires_at": 0})
        engine.expire()
        self.assertEqual(store.get("blocks", row["id"])["status"], "released")
        store.close()

    def test_active_failure_not_claimed_success(self):
        settings = self.settings()
        settings.firewall_mode = "active"
        class Broken:
            def apply(self, *args):
                raise OSError("denied")
        store = Store(settings.data_dir / "failed.sqlite")
        engine = ResponseEngine(store, settings, lambda *a, **k: None, lambda: [], Broken())
        self.assertEqual(engine.block(SOURCE, "test")["status"], "cleanup_required")
        self.assertEqual(engine.block("10.77.0.56", "test", "demo")["status"], "simulated_block")
        store.close()

    def test_api_full_demo_and_auth(self):
        app = create_app(self.settings())
        with TestClient(app, client=("127.0.0.1", 40000)) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.post("/api/firewall/block", json={"ip":"127.0.0.1","reason":"test"}).status_code,400)
            self.assertEqual(client.post("/api/devices",json={"id":"esp32","name":"Sensor","ip":"10.77.0.22"}).status_code,200)
            self.assertEqual(client.post("/api/devices",json={"id":"other","name":"Sensor","ip":"10.77.0.22"}).status_code,400)
            service = app.state.service
            for index, scenario in enumerate(("normal", "port_scan", "port_scan")):
                service.process(self.window(scenario, 100+index*5), "demo")
            state = client.get("/api/system/status").json()
            self.assertEqual(len(state["alerts"]), 1)
            self.assertEqual(len(state["detections"]), 2)
            self.assertEqual(state["blocks"][0]["status"], "simulated_block")
            self.assertTrue(service.response.denied_demo(SOURCE))
            self.assertFalse(state["models"]["live"]["ready"])
            with client.websocket_connect("/ws/events") as ws:
                ws.send_json({"token":""})
                self.assertIn("devices",ws.receive_json())
            self.assertEqual(client.post("/api/simulation/start",json={"scenario":"bad"}).status_code,400)
            self.assertEqual(client.post("/api/simulation/start",json={"scenario":"port_scan"}).status_code,200)
            self.assertEqual(client.post("/api/simulation/start",json={"scenario":"port_scan"}).status_code,400)
            self.assertEqual(client.post("/api/simulation/stop",json={}).status_code,200)
        app = create_app(self.settings())
        with TestClient(app, client=("10.77.0.44",40000)) as client:
            self.assertEqual(client.get("/api/system/status").status_code,401)

    def test_sensor_auth_and_demo_isolation(self):
        settings = self.settings()
        app = create_app(settings)
        service = app.state.service
        service.store.put("devices",dict(id="sensor",ip="127.0.0.1",name="test",type="test",origin="live"))
        body = dict(device_id="sensor",sequence=1,device_uptime_ms=1000,temperature_c=30,humidity_percent=50)
        with TestClient(app, client=("127.0.0.1",40000)) as client:
            self.assertEqual(client.post("/api/telemetry",json=body).status_code,401)
            response = client.post("/api/telemetry",json=body,headers={"X-IoT-Token":"test-sensor"})
            self.assertEqual(response.status_code,202)
            self.assertEqual(response.headers["x-iot-security-status"],"UNKNOWN")
            self.assertEqual(client.post("/api/telemetry",json=body,headers={"X-IoT-Token":"test-sensor"}).status_code,409)


if __name__ == "__main__":
    unittest.main()
