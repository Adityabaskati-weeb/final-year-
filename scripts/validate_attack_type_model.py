"""Validate an attack-family artifact on the manifest's independent test captures."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import joblib
from sklearn.metrics import accuracy_score, classification_report, f1_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.features import SCHEMA
from ml.train_attack_type import load_rows, matrix


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    bundle = joblib.load(args.model)
    if bundle.get("schema") != SCHEMA or bundle.get("task") != "attack_type":
        raise ValueError("Model is not a schema-matched attack-family artifact")
    rows, _ = load_rows(args.manifest)
    test = [row for row in rows if row["split"] == "test"]
    if len({row["capture"] for row in test}) < 2:
        raise ValueError("Independent attack-family validation requires two or more test captures")
    truth = [row["attack_type"] for row in test]
    classes = list(bundle["model"].classes_)
    predicted = bundle["model"].predict(matrix([row["features"] for row in test]))
    model_hash = hashlib.sha256(args.model.read_bytes()).hexdigest()
    report = {
        "task": "attack_type", "schema": SCHEMA, "provenance": "labelled_lab_capture",
        "model_sha256": model_hash, "independent_sessions": True,
        "rows": len(test), "capture_ids": sorted({row["capture"] for row in test}),
        "classes": classes, "accuracy": float(accuracy_score(truth, predicted)),
        "macro_f1": float(f1_score(truth, predicted, labels=classes, average="macro", zero_division=0)),
        "classification_report": classification_report(
            truth, predicted, labels=classes, output_dict=True, zero_division=0,
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["macro_f1"] < 0.8:
        raise SystemExit("Attack-family validation gate failed")


if __name__ == "__main__":
    main()
