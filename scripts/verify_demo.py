"""Verify an already running local dry-run server. No network attack is sent."""
import argparse
import time
import httpx

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port",type=int,default=8020)
    args = parser.parse_args()
    with httpx.Client(base_url=f"http://127.0.0.1:{args.port}", timeout=10) as client:
        before = time.time()
        state = client.get("/api/system/status").json()
        assert state["firewall_mode"] == "dry-run", "Run only against dry-run server"
        client.post("/api/simulation/stop", json={}).raise_for_status()
        client.post("/api/simulation/start", json={"scenario":"port_scan"}).raise_for_status()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = client.get("/api/system/status").json()
            if not state["simulation"]:
                break
            time.sleep(.5)
        kinds = {e["kind"] for e in state["events"] if e["timestamp"] >= before}
        required = {"SENSOR_CONNECTED","ATTACK_STARTED","ATTACK_DETECTED","RESPONSE_TRIGGERED",
                    "FIREWALL_SIMULATED_BLOCK","SIMULATED_TRAFFIC_REJECTED","DEMO_STOPPED"}
        assert required <= kinds, f"Missing stages: {required-kinds}"
        assert not state["models"]["live"]["ready"], "This smoke test expects the default untrained-live setup"
        print("PASS: sensor -> normal/attack features -> ML detection -> simulated block -> rejected packets")
        print("No real attack traffic or OS firewall rule was generated")
