"""Build a checksum-checked training manifest from labelled lab flow captures."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.features import read_log


def build_manifest(input_dir, output, split=None, default_attack_type=None):
    entries, captures, hashes = [], set(), set()
    for file in sorted(Path(input_dir).glob("*.jsonl")):
        metadata_path = file.with_suffix(file.suffix + ".json")
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        if metadata.get("provenance") != "labelled_lab_capture":
            raise ValueError(f"{file}: labelled_lab_capture provenance required")
        capture_id, metadata_split = metadata.get("capture_id"), metadata.get("split")
        if split is not None and metadata_split != split:
            continue
        if capture_id in captures or metadata_split not in {"train", "validation", "test"}:
            raise ValueError("Capture IDs must be unique and splits must be train, validation or test")
        digest = hashlib.sha256(file.read_bytes()).hexdigest()
        if digest != metadata.get("sha256") or digest in hashes:
            raise ValueError(f"{file}: capture checksum mismatch or duplicate content")
        rows = list(read_log(file))
        if not rows or any(row.get("label") not in {"benign", "malicious"} for row in rows):
            raise ValueError(f"{file}: every flow must carry an explicit binary label")
        device_id = metadata.get("device_id") or metadata.get("target")
        label = metadata.get("label")
        attack_type = metadata.get("attack_type")
        if not attack_type and label == "benign":
            attack_type = "normal"
        if not attack_type and label == "malicious":
            attack_type = default_attack_type
        if label == "malicious" and not attack_type:
            raise ValueError(f"{file}: malicious capture requires attack_type metadata or --default-attack-type")
        if not device_id or not attack_type:
            raise ValueError(f"{file}: device_id and attack_type metadata are required")
        captures.add(capture_id)
        hashes.add(digest)
        entries.append({
            "path": str(file.resolve()),
            "capture_id": capture_id,
            "device_id": device_id,
            "attack_type": attack_type,
            "split": metadata_split,
            "provenance": "labelled_lab_capture",
            "extractor": metadata.get("extractor"),
            "sha256": digest,
            "rows": len(rows),
        })
    if not entries:
        raise ValueError("No labelled .jsonl captures found")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    print(json.dumps(entries, indent=2))
    return entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split", choices=("train", "validation", "test"))
    parser.add_argument("--default-attack-type", help="Required fallback label for malicious captures without attack_type metadata")
    args = parser.parse_args()
    build_manifest(args.input_dir, args.output, args.split, args.default_attack_type)


if __name__ == "__main__":
    main()
