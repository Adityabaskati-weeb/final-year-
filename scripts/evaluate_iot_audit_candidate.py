"""Evaluate the published iot-audit pipeline on real IoT-23 test captures."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from sklearn.metrics import accuracy_score, average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.features import binary_label, read_log  # noqa: E402
from backend.iot_audit_candidate import ARTIFACT_SHA256, FEATURES, IoTAuditCandidate, build_features  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default=str(ROOT / "runtime/iot-audit-pretrained/binary_lightgbm.joblib"))
    parser.add_argument("--output", default=str(ROOT / "runtime/iot-audit-pretrained/evaluation.json"))
    parser.add_argument("--split", default="test")
    args = parser.parse_args()

    candidate = IoTAuditCandidate(args.model)
    if candidate.pipeline is None:
        raise SystemExit(candidate.error)
    manifest_path = ROOT / "runtime/iot23/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    selected = [item for item in manifest if item["split"] == args.split]
    y_true, y_pred, scores = [], [], []
    compatible_records = []
    captures = []
    skipped = 0
    started = time.perf_counter()
    for item in selected:
        path = ROOT / "runtime/iot23" / item["path"]
        captures.append(item["capture_id"])
        for raw in read_log(path):
            try:
                expected = 1 if binary_label(raw) == "attack" else 0
                build_features(raw)
                compatible_records.append((expected, raw))
            except (KeyError, TypeError, ValueError):
                skipped += 1
                continue

    results = candidate.predict_many([raw for _, raw in compatible_records])
    for (expected, _), result in zip(compatible_records, results):
        y_true.append(expected)
        y_pred.append(1 if result["prediction"] == "malicious" else 0)
        scores.append(result["attack_probability"])

    if not y_true:
        raise SystemExit("No compatible real IoT-23 rows were evaluated")
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    tn, fp, fn, tp = matrix[0][0], matrix[0][1], matrix[1][0], matrix[1][1]
    report = {
        "report_version": "iot-audit-candidate-on-iot23-v1",
        "artifact_sha256": ARTIFACT_SHA256,
        "artifact_status": candidate.status(),
        "source_dataset": "IoT-23",
        "source_split": args.split,
        "source_captures": captures,
        "rows": len(y_true),
        "skipped_rows": skipped,
        "features": FEATURES,
        "label_mapping": {"0": "normal/benign", "1": "attack/malicious"},
        "metrics": {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_true, scores)) if len(set(y_true)) > 1 else None,
            "average_precision": float(average_precision_score(y_true, scores)) if len(set(y_true)) > 1 else None,
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
            "false_negative_rate": float(fn / (fn + tp)) if (fn + tp) else None,
        },
        "confusion_matrix_normal_attack": matrix,
        "elapsed_seconds": time.perf_counter() - started,
        "live_validated": False,
        "eligible": False,
        "scope": "Offline domain-shift evaluation: TON-IoT pretrained pipeline applied to real IoT-23 Zeek captures",
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
