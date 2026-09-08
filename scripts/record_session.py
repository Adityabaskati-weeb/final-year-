"""Bounded passive PCAP recording. Sends no network traffic."""
import argparse
import ipaddress
from pathlib import Path
from scapy.all import sniff, PcapWriter

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--target", required=True, type=ipaddress.ip_address)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 100 <= args.seconds <= 600:
        parser.error("Use 100-600 seconds per independent session")
    if args.output.exists():
        parser.error("Output already exists; choose a new session file")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with PcapWriter(str(args.output), sync=True) as writer:
        sniff(iface=args.interface, filter="host " + str(args.target), timeout=args.seconds,
              count=100000, store=False, prn=writer.write)
    print("Recorded", args.output, "- label the session from your experiment log, not model predictions")
