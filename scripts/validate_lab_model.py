"""Evaluate a lab-trained model on independent labelled flow captures."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.features import FEATURES, SCHEMA, features, read_log
from ml.train import metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True, help="Test-only labelled manifest")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = joblib.load(args.model)
    if bundle.get("schema") != SCHEMA or bundle.get("features") != FEATURES:
        raise ValueError("Model and validation schema do not match")
    entries = json.loads(args.manifest.read_text(encoding="utf-8"))
    model_captures = {source["capture_id"] for source in bundle["report"].get("sources", [])
                      if source.get("split") in {"train", "validation"}}
    rows, capture_ids, extractors = [], set(), set()
    for entry in entries:
        if entry.get("split") != "test":
            raise ValueError("Validation manifest must contain only test captures")
        if entry["capture_id"] in model_captures:
            raise ValueError("Validation capture overlaps the model training manifest")
        file = Path(entry["path"])
        with file.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != entry["sha256"]:
                raise ValueError(f"Checksum mismatch: {file}")
        for raw in read_log(file):
            if raw.get("label") not in {"benign", "malicious"}:
                raise ValueError("Validation rows require benign/malicious labels")
            capture_ids.add(entry["capture_id"])
            extractors.add(raw.get("extractor"))
            rows.append((features(raw), "normal" if raw["label"] == "benign" else "attack"))
    if not rows or len(capture_ids) < 2 or len(extractors) != 1:
        raise ValueError("Need non-empty, multi-session validation with one extractor version")
    array = np.array([[np.nan if row[name] is None else row[name] for name in FEATURES]
                      for row, _ in rows], dtype=object)
    labels = [label for _, label in rows]
    threshold = bundle["report"]["threshold"]
    scores = bundle["model"].predict_proba(array)[:, list(bundle["model"].classes_).index("attack")]
    result = metrics(labels, scores, threshold)
    result.update({
        "provenance": "labelled_lab_capture",
        "schema": SCHEMA,
        "model_sha256": hashlib.sha256(args.model.read_bytes()).hexdigest(),
        "independent_sessions": True,
        "capture_ids": sorted(capture_ids),
        "attack_samples": labels.count("attack"),
        "normal_samples": labels.count("normal"),
        "recall": result["recall"],
        "false_positive_rate": result["false_positive_rate"],
        "extractor_version": next(iter(extractors)),
        "extractor_config": {"interface": "lab-configured", "target_scope": "registered-private-device"},
        "model_scope": bundle["report"].get("scope"),
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if result["attack_samples"] < 20 or result["normal_samples"] < 100:
        raise SystemExit("Validation evidence is below the minimum sample gate")
    if result["recall"] < 0.8 or result["false_positive_rate"] > 0.05:
        raise SystemExit("Validation quality gate failed")


if __name__ == "__main__":
    main()
