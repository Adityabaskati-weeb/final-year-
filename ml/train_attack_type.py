"""Train a schema-matched multiclass attack-family model from labelled lab flows."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

import joblib
import numpy as np
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from backend.features import FEATURES, NUMERIC, SCHEMA, binary_label, features, read_log


def matrix(rows):
    return np.array([[np.nan if row[name] is None else row[name] for name in FEATURES]
                     for row in rows], dtype=object)


def load_rows(manifest_path, max_per_capture=100000):
    manifest_path = Path(manifest_path)
    entries = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows, sources = [], []
    seen_captures, seen_hashes = set(), set()
    for entry in entries:
        capture_id, split = entry.get("capture_id"), entry.get("split")
        attack_type = entry.get("attack_type")
        if not capture_id or capture_id in seen_captures:
            raise ValueError("Capture IDs must be unique")
        if split not in {"train", "validation", "test"}:
            raise ValueError("Invalid capture split")
        if entry.get("provenance") != "labelled_lab_capture":
            raise ValueError("Attack-family training requires labelled private lab captures")
        if not attack_type or attack_type in {"unknown", "unspecified"}:
            raise ValueError(f"{capture_id}: explicit attack_type is required")
        path = (manifest_path.parent / entry["path"]).resolve()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != entry.get("sha256") or digest in seen_hashes:
            raise ValueError(f"{capture_id}: checksum mismatch or duplicate capture")
        seen_captures.add(capture_id)
        seen_hashes.add(digest)
        capture_rows = []
        for record in read_log(path):
            label = binary_label(record)
            actual_type = "normal" if label == "normal" else attack_type
            if record.get("attack_type") not in {None, actual_type}:
                raise ValueError(f"{capture_id}: row attack_type conflicts with manifest")
            capture_rows.append({"features": features(record), "attack_type": actual_type,
                                 "capture": capture_id, "split": split})
        rows.extend(capture_rows[:max_per_capture])
        sources.append({**entry, "rows_used": min(len(capture_rows), max_per_capture)})
    if not rows:
        raise ValueError("No labelled rows found")
    return rows, sources


def make_pipeline():
    preprocessing = ColumnTransformer([
        ("numeric", SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True),
         list(range(len(NUMERIC)))),
        ("categorical", OneHotEncoder(handle_unknown="ignore"),
         list(range(len(NUMERIC), len(FEATURES)))),
    ])
    return Pipeline([
        ("preprocessing", preprocessing),
        ("classifier", RandomForestClassifier(
            n_estimators=250, max_depth=24, min_samples_leaf=2,
            class_weight="balanced_subsample", random_state=42, n_jobs=1,
        )),
    ])


def partition(rows, name):
    result = [row for row in rows if row["split"] == name]
    captures = {row["capture"] for row in result}
    classes = {row["attack_type"] for row in result}
    if len(captures) < 2 or "normal" not in classes or len(classes) < 3:
        raise ValueError(f"{name} requires two captures, normal, and two attack families")
    return result


def train(manifest, output, max_per_capture=100000):
    output = Path(output)
    if output.exists() and any((output / name).exists() for name in ("model.joblib", "evaluation.json")):
        raise FileExistsError("Output contains an existing model; choose a new versioned folder")
    rows, sources = load_rows(manifest, max_per_capture)
    partitions = {name: partition(rows, name) for name in ("train", "validation", "test")}
    pipeline = make_pipeline()
    training = partitions["train"]
    pipeline.fit(matrix([row["features"] for row in training]),
                 [row["attack_type"] for row in training])
    classes = list(pipeline.classes_)
    metrics = {}
    for name, values in partitions.items():
        truth = [row["attack_type"] for row in values]
        predicted = pipeline.predict(matrix([row["features"] for row in values]))
        metrics[name] = {
            "rows": len(values),
            "accuracy": float(accuracy_score(truth, predicted)),
            "macro_f1": float(f1_score(truth, predicted, labels=classes, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(truth, predicted, labels=classes, average="weighted", zero_division=0)),
            "classification_report": classification_report(
                truth, predicted, labels=classes, output_dict=True, zero_division=0,
            ),
            "class_counts": dict(Counter(truth)),
            "capture_ids": sorted({row["capture"] for row in values}),
        }
    report = {
        "report_version": "real-lab-attack-type-v1", "schema": SCHEMA,
        "features": FEATURES, "provenance": "real_lab_capture", "task": "attack_type",
        "classes": classes, "metrics": metrics, "sources": sources,
        "scope": "Private lab captures with the same extractor as live inference",
        "live_validated": False, "eligible": metrics["validation"]["macro_f1"] >= 0.8,
        "trained_at": time.time(), "sklearn_version": sklearn.__version__,
    }
    output.mkdir(parents=True, exist_ok=True)
    artifact = {"model": pipeline, "schema": SCHEMA, "features": FEATURES,
                "provenance": "real_lab_capture", "task": "attack_type",
                "sklearn_version": sklearn.__version__, "report": report}
    joblib.dump(artifact, output / "model.joblib")
    (output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-per-capture", type=int, default=100000)
    args = parser.parse_args()
    if not 100 <= args.max_per_capture <= 500000:
        parser.error("max-per-capture must be 100..500000")
    print(json.dumps(train(args.manifest, args.output, args.max_per_capture), indent=2))
