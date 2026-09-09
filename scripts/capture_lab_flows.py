"""Capture one explicitly labelled, bounded flow session from an owned lab device.

This records packets passively. The label describes the experiment phase supplied
by the operator; the script never launches traffic or infers a ground truth label.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.lab import authorized_target
from backend.packet_capture import ScapyFlowCapture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--label", choices=("normal", "attack"), required=True)
    parser.add_argument(
        "--device-id",
        default=None,
        help="Stable lab device identifier; defaults to the authorized target IP",
    )
    parser.add_argument(
        "--attack-type",
        default=None,
        help="Observed attack-family label for later multiclass work (not inferred by this recorder)",
    )
    parser.add_argument("--split", choices=("train", "validation", "test"), required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--port", type=int, help="Keep only flows involving this target port")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lab-config", type=Path, default=ROOT / "config/lab_targets.yaml")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.capture_id):
        parser.error("capture-id must contain only letters, numbers, dot, underscore or hyphen")
    device_id = args.device_id or args.target
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", device_id):
        parser.error("device-id must contain only letters, numbers, dot, colon, underscore or hyphen")
    attack_type = "normal" if args.label == "normal" else (args.attack_type or "unknown")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", attack_type):
        parser.error("attack-type must contain only letters, numbers, dot, underscore or hyphen")
    if args.label == "normal" and attack_type != "normal":
        parser.error("normal captures must use attack-type=normal")
    if not 5 <= args.seconds <= 600:
        parser.error("seconds must be between 5 and 600")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    target = authorized_target(args.lab_config, args.target)
    metadata = args.output.with_suffix(args.output.suffix + ".json")
    if args.output.exists() or metadata.exists():
        parser.error("Output already exists; choose a new capture ID/path")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    capture = ScapyFlowCapture(args.interface, {target})
    started = time.time()
    error = None
    try:
        capture.start()
        time.sleep(args.seconds)
    except Exception as exception:
        error = str(exception)
    finally:
        try:
            capture.stop()
        except Exception as exception:
            error = error or str(exception)
    rows = capture.poll()
    if args.port is not None:
        rows = [row for row in rows if args.port in (row["id.orig_p"], row["id.resp_p"])]
    label = "benign" if args.label == "normal" else "malicious"
    with args.output.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps({
                **row,
                "label": label,
                "capture_id": args.capture_id,
                "device_id": device_id,
                "attack_type": attack_type,
            }) + "\n")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    result = {
        "provenance": "labelled_lab_capture",
        "extractor": capture.extractor,
        "capture_id": args.capture_id,
        "device_id": device_id,
        "split": args.split,
        "target": target,
        "interface": args.interface,
        "label": label,
        "attack_type": attack_type,
        "started_at": started,
        "ended_at": time.time(),
        "seconds": args.seconds,
        "port_filter": args.port,
        "packet_count": capture.packet_count,
        "flow_count": len(rows),
        "path": str(args.output.resolve()),
        "sha256": digest,
        "error": error or capture.error,
        "status": "captured" if rows and not (error or capture.error) else "incomplete",
        "note": "Labels describe an explicitly observed private-lab experiment; this recorder never generates traffic or infers attack type.",
    }
    metadata.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if result["status"] != "captured":
        raise SystemExit("No complete labelled flow capture was produced")


if __name__ == "__main__":
    main()
