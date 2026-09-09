"""Bounded passive PCAP recording from an allowlisted lab device. Sends no packets."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.lab import authorized_target


def main():
    from scapy.all import sniff, PcapWriter, conf
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--interface")
    parser.add_argument("--target")
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--lab-config", type=Path, default=ROOT / "config/lab_targets.yaml")
    args = parser.parse_args()
    if args.list_interfaces:
        print(conf.ifaces)
        return
    if not args.interface or not args.target or not args.output:
        parser.error("interface, target and output are required")
    if not 1 <= args.seconds <= 600:
        parser.error("Use 1-600 seconds per recording")
    target = authorized_target(args.lab_config, args.target)
    metadata = args.output.with_suffix(args.output.suffix + ".json")
    if args.output.exists() or metadata.exists():
        parser.error("Output already exists; choose a new recording")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    count, started, error = 0, time.time(), None
    try:
        with PcapWriter(str(args.output), sync=True) as writer:
            def write(packet):
                nonlocal count
                writer.write(packet)
                count += 1
            sniff(iface=args.interface, filter="host " + target, timeout=args.seconds,
                  count=100000, store=False, prn=write)
    except Exception as exception:
        error = str(exception)
    digest = None
    if args.output.exists():
        with args.output.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
    result = dict(provenance="passive_lab_capture", target=target, interface=args.interface,
                  started_at=started, ended_at=time.time(), packet_count=count, pcap=str(args.output.resolve()),
                  sha256=digest, error=error, label=None, status="captured" if count and not error else "incomplete",
                  note="No labels inferred. Retain an independent experiment log; no attack was generated.")
    metadata.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if error or not count:
        raise SystemExit("No complete nonempty capture. Check interface/permissions/visibility; do not substitute data.")


if __name__ == "__main__":
    main()
