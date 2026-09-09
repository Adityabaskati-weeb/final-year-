"""Run a small, allowlisted TCP connection probe against an owned lab target.

This is intentionally bounded and is provided only to create a repeatable lab
traffic phase for validation. It does not scan a range, evade controls, or run
continuously. Use the current private device IP and document the experiment.
"""
import argparse
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.lab import authorized_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--connections", type=int, default=25)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--lab-config", type=Path, default=ROOT / "config/lab_targets.yaml")
    args = parser.parse_args()
    target = authorized_target(args.lab_config, args.target)
    if not 1 <= args.port <= 65535 or not 1 <= args.connections <= 50 or not 0 <= args.interval_ms <= 5000:
        parser.error("port, connections or interval outside the bounded lab limits")
    results = {"target": target, "port": args.port, "connections": args.connections,
               "started_at": time.time(), "attempts": []}
    for _ in range(args.connections):
        started = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(0.25)
            code = client.connect_ex((target, args.port))
        results["attempts"].append({"result_code": code, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
        if args.interval_ms:
            time.sleep(args.interval_ms / 1000)
    results["ended_at"] = time.time()
    print(results)


if __name__ == "__main__":
    main()
