"""python -m ml.train --demo OR --manifest labelled-sessions.json."""
import argparse
import hashlib
import json
from pathlib import Path
import time

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score,
    fbeta_score, roc_auc_score, average_precision_score, confusion_matrix, classification_report)

from backend.config import ROOT
from backend.features import FEATURES, SCHEMA, SECONDS, Windows, Packet, vector
from backend.simulation import dataset


def from_manifest(path):
    from scapy.all import PcapReader
    path = Path(path)
    entries = json.loads(path.read_text(encoding="utf-8"))
    seen, groups, rows = set(), set(), []
    for entry in entries:
        pcap = (path.parent / entry["pcap"]).resolve()
        with pcap.open("rb") as file:
            digest = hashlib.file_digest(file, "sha256").hexdigest()
        if digest in seen or entry["session"] in groups:
            raise ValueError("Duplicate PCAP/session across dataset")
        if entry["split"] not in {"train", "test"} or not entry.get("notes", "").strip():
            raise ValueError("Each recording needs train/test split and scenario notes")
        seen.add(digest)
        groups.add(entry["session"])
        extractor = Windows()
        for target in entry["targets"]:
            import ipaddress
            ipaddress.ip_address(target)
        count = 0
        with PcapReader(str(pcap)) as stream:
            for raw in stream:
                packet = Packet.from_scapy(raw)
                if packet and packet.destination in entry["targets"]:
                    for row in extractor.push(packet):
                        rows.append({**row, "label": entry["label"], "session": entry["session"],
                                     "split": entry["split"], "sha256": digest})
                        count += 1
                        if len(rows) > 100000:
                            raise ValueError("Dataset exceeds 100000 windows")
        if count < 20:
            raise ValueError("Each PCAP needs 20 completed windows; final incomplete window discarded")
        if extractor.dropped:
            raise ValueError("Out-of-order packets or capacity loss in training PCAP")
    return rows


def train(rows, output, provenance):
    if provenance not in {"synthetic_demo", "real_capture"}:
        raise ValueError("Unknown dataset provenance")
    train_rows = [row for row in rows if row["split"] == "train"]
    test_rows = [row for row in rows if row["split"] == "test"]
    if not train_rows or not test_rows:
        raise ValueError("Both training and test sessions are required")
    if {r["session"] for r in train_rows} & {r["session"] for r in test_rows}:
        raise ValueError("Train/test session leakage")
    classes = set(r["label"] for r in rows)
    if "normal" not in classes or len(classes) < 2:
        raise ValueError("Need normal and at least one attack class")
    for split_rows in (train_rows, test_rows):
        for label in classes:
            if len({r["session"] for r in split_rows if r["label"] == label}) < 2:
                raise ValueError("Each class needs two independent sessions in each split")
    x = np.array([vector(r["features"]) for r in train_rows])
    y = [r["label"] for r in train_rows]
    xt = np.array([vector(r["features"]) for r in test_rows])
    yt = np.array([r["label"] for r in test_rows])
    model = RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_leaf=2,
                                   class_weight="balanced", random_state=42, n_jobs=1)
    model.fit(x, y)
    probabilities = model.predict_proba(xt)
    scores = 1 - probabilities[:, list(model.classes_).index("normal")]
    binary = yt != "normal"
    predictions = scores >= 0.8
    labels = model.predict(xt)
    latency = []
    for row in xt[:100]:
        before = time.perf_counter()
        model.predict_proba([row])
        latency.append((time.perf_counter() - before) * 1000)
    tn, fp, fn, tp = confusion_matrix(binary, predictions, labels=[False, True]).ravel()
    report = {"provenance": provenance, "schema": SCHEMA,
        "binary_accuracy": float(accuracy_score(binary, predictions)),
        "precision": float(precision_score(binary, predictions, zero_division=0)),
        "recall": float(recall_score(binary, predictions, zero_division=0)),
        "f1": float(f1_score(binary, predictions, zero_division=0)),
        "f2": float(fbeta_score(binary, predictions, beta=2, zero_division=0)),
        "roc_auc": float(roc_auc_score(binary, scores)),
        "pr_auc_average_precision": float(average_precision_score(binary, scores)),
        "false_positive_rate": float(fp / (tn + fp)),
        "confusion_matrix_normal_attack": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "multiclass": classification_report(yt, labels, output_dict=True, zero_division=0),
        "inference_ms_p50": float(np.median(latency)), "inference_ms_p95": float(np.percentile(latency, 95)),
        "train_windows": len(train_rows), "test_windows": len(test_rows),
        "train_sessions": sorted({r["session"] for r in train_rows}),
        "test_sessions": sorted({r["session"] for r in test_rows}),
        "pcap_hashes": sorted({r["sha256"] for r in rows if "sha256" in r}),
        "threshold": 0.8, "scope": "Synthetic scenarios only" if provenance == "synthetic_demo" else "Recorded lab scenarios only"}
    report["eligible"] = report["recall"] >= 0.8 and report["false_positive_rate"] <= 0.05
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not report["eligible"]:
        raise ValueError("Evaluation gate failed; no artifact exported")
    artifact = {"model": model, "features": FEATURES, "schema": SCHEMA, "window_seconds": SECONDS,
                "sklearn_version": sklearn.__version__, "provenance": provenance, "report": report,
                "normal_median": np.median(x[np.array(y) == "normal"], axis=0).tolist()}
    temp = output / "model.tmp"
    joblib.dump(artifact, temp)
    temp.replace(output / "model.joblib")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--demo", action="store_true")
    group.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    provenance = "synthetic_demo" if args.demo else "real_capture"
    result = train(dataset() if args.demo else from_manifest(args.manifest),
                   args.output or ROOT / "runtime" / ("demo-model" if args.demo else "live-model"), provenance)
    print(json.dumps(result, indent=2))
