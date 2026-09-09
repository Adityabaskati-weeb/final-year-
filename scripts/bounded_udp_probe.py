"""Send a bounded UDP probe only to an explicitly allowlisted private lab target.

This is a controlled traffic phase for an owned test device. It does not scan,
spoof, evade controls, or run continuously. Capture it separately and label
the resulting session as ``udp_probe`` only when the experiment was observed.
"""
import argparse
from pathlib import Path
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.lab import authorized_target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--datagrams", type=int, default=25)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--payload-bytes", type=int, default=8)
    parser.add_argument("--lab-config", type=Path, default=ROOT / "config/lab_targets.yaml")
    args = parser.parse_args()
    target = authorized_target(args.lab_config, args.target)
    if not 1 <= args.port <= 65535 or not 1 <= args.datagrams <= 50:
        parser.error("port or datagrams outside the bounded lab limits")
    if not 0 <= args.interval_ms <= 5000 or not 1 <= args.payload_bytes <= 32:
        parser.error("interval or payload size outside the bounded lab limits")

    payload = b"L" * args.payload_bytes
    results = {"target": target, "port": args.port, "datagrams": args.datagrams,
               "payload_bytes": args.payload_bytes, "started_at": time.time(),
               "attempts": []}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(0.25)
        for _ in range(args.datagrams):
            started = time.perf_counter()
            try:
                sent = client.sendto(payload, (target, args.port))
                result = {"sent": sent, "result": "sent"}
            except OSError as error:
                result = {"sent": 0, "result": "error", "error": str(error)}
            results["attempts"].append({**result,
                                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
            if args.interval_ms:
                time.sleep(args.interval_ms / 1000)
    results["ended_at"] = time.time()
    print(results)


if __name__ == "__main__":
    main()
