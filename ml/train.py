"""Train a binary Random Forest exclusively from labelled real Zeek logs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import time

import joblib
import numpy as np
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (accuracy_score, precision_score, recall_score, f1_score, fbeta_score,
                            roc_auc_score, average_precision_score, confusion_matrix)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from backend.features import FEATURES, NUMERIC, SCHEMA, features, binary_label, read_log


def matrix(rows):
    return np.array([[np.nan if row[name] is None else row[name] for name in FEATURES] for row in rows], dtype=object)


def class_distribution(labels):
    counts = Counter(labels)
    total = len(labels)
    return {
        "normal": int(counts.get("normal", 0)),
        "attack": int(counts.get("attack", 0)),
        "total": total,
        "proportions": {
            "normal": float(counts.get("normal", 0) / total) if total else None,
            "attack": float(counts.get("attack", 0) / total) if total else None,
        },
    }


def load_manifest(path, cap=100000):
    path = Path(path)
    entries = json.loads(path.read_text(encoding="utf-8"))
    groups, hashes, rows, sources = set(), set(), [], []
    for entry in entries:
        capture, split = entry["capture_id"], entry["split"]
        if capture in groups or split not in {"train", "validation", "test"}:
            raise ValueError("Repeated capture or invalid split")
        if entry.get("provenance") not in {"iot23_official", "labelled_lab_capture"}:
            raise ValueError("Real labelled capture provenance required")
        file = (path.parent / entry["path"]).resolve()
        with file.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != entry["sha256"] or digest in hashes:
            raise ValueError("Data integrity failure or duplicate capture content")
        groups.add(capture)
        hashes.add(digest)
        rng = random.Random(42)
        sample, counts = [], Counter()
        for index, record in enumerate(read_log(file)):
            row = dict(features=features(record), label=binary_label(record), capture=capture, split=split)
            counts[row["label"]] += 1
            if len(sample) < cap:
                sample.append(row)
            else:
                j = rng.randint(0, index)
                if j < cap:
                    sample[j] = row
        rows.extend(sample)
        sources.append({**entry, "rows_scanned": sum(counts.values()), "rows_used": len(sample), "class_counts": dict(counts)})
    return rows, sources


def metrics(labels, scores, threshold):
    scores = np.asarray(scores)
    if len(labels) != len(scores) or not labels:
        raise ValueError("Metrics require equally sized, non-empty labels and scores")
    truth = np.array(labels) == "attack"
    predicted = scores >= threshold
    tn, fp, fn, tp = confusion_matrix(truth, predicted, labels=[False, True]).ravel()
    auc_defined = len(np.unique(truth)) == 2
    return dict(binary_accuracy=float(accuracy_score(truth, predicted)),
        precision=float(precision_score(truth, predicted, zero_division=0)),
        recall=float(recall_score(truth, predicted, zero_division=0)),
        f1=float(f1_score(truth, predicted, zero_division=0)),
        f2=float(fbeta_score(truth, predicted, beta=2, zero_division=0)),
        roc_auc=float(roc_auc_score(truth, scores)) if auc_defined else None,
        pr_auc_average_precision=float(average_precision_score(truth, scores)) if auc_defined else None,
        auc_defined=auc_defined,
        auc_note=None if auc_defined else "undefined: labels contain one class",
        false_positive_rate=float(fp / (tn + fp)) if (tn + fp) else None,
        false_negative_rate=float(fn / (fn + tp)) if (fn + tp) else None,
        confusion_matrix_normal_attack=[[int(tn), int(fp)], [int(fn), int(tp)]])


def make_pipeline():
    numeric = SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)
    preprocessing = ColumnTransformer([
        ("numeric", numeric, list(range(len(NUMERIC)))),
        ("categorical", OneHotEncoder(handle_unknown="ignore"), list(range(len(NUMERIC), len(FEATURES))))])
    return Pipeline([("preprocessing", preprocessing),
        ("classifier", RandomForestClassifier(n_estimators=150, max_depth=18, min_samples_leaf=3,
                                             class_weight="balanced_subsample", random_state=42, n_jobs=1))])


def choose_threshold(labels, scores):
    candidates = [(float(t), metrics(labels, scores, t)) for t in np.linspace(.5, .99, 50)]
    acceptable = [pair for pair in candidates
                  if pair[1]["false_positive_rate"] is not None
                  and pair[1]["false_positive_rate"] <= .05]
    return max(acceptable or candidates,
               key=lambda p: (p[1]["f2"] if acceptable else -p[1]["false_positive_rate"], p[0]))


def exact_feature_filter(partitions):
    """Retain the historical exact-overlap diagnostic without changing primary data."""
    filtered, exclusions = {}, {}
    seen = set()
    for split in ("train", "validation", "test"):
        kept, current = [], set()
        for row in partitions[split]:
            key = json.dumps(row["features"], sort_keys=True, allow_nan=False)
            if key not in seen:
                kept.append(row)
                current.add(key)
        filtered[split] = kept
        exclusions[split] = len(partitions[split]) - len(kept)
        seen.update(current)
    return filtered, exclusions


def capture_counts(before, after):
    result = {}
    for split in ("train", "validation", "test"):
        captures = sorted({row["capture"] for row in before[split]})
        result[split] = {}
        for capture in captures:
            before_rows = [row for row in before[split] if row["capture"] == capture]
            after_rows = [row for row in after[split] if row["capture"] == capture]
            result[split][capture] = {
                "before": class_distribution([row["label"] for row in before_rows]),
                "after_exact_feature_exclusion": class_distribution(
                    [row["label"] for row in after_rows]) if after_rows else class_distribution([]),
            }
    return result


def evaluate_partition(pipeline, rows, threshold):
    scores = pipeline.predict_proba(matrix([row["features"] for row in rows]))[:,
        list(pipeline.classes_).index("attack")]
    labels = [row["label"] for row in rows]
    aggregate = metrics(labels, scores, threshold)
    per_capture = {}
    for capture in sorted({row["capture"] for row in rows}):
        indices = [index for index, row in enumerate(rows) if row["capture"] == capture]
        capture_labels = [labels[index] for index in indices]
        capture_scores = scores[indices]
        per_capture[capture] = dict(
            split="test",
            rows=len(indices),
            class_distribution=class_distribution(capture_labels),
            **metrics(capture_labels, capture_scores, threshold))
    return aggregate, per_capture, scores


def fit_evaluate(partitions):
    pipeline = make_pipeline()
    training = partitions["train"]
    pipeline.fit(matrix([r["features"] for r in training]), [r["label"] for r in training])
    validation = partitions["validation"]
    validation_scores = pipeline.predict_proba(matrix([r["features"] for r in validation]))[:,
        list(pipeline.classes_).index("attack")]
    threshold, validation_metrics = choose_threshold(
        [r["label"] for r in validation], validation_scores)
    testing = partitions["test"]
    test_metrics, per_capture_test_metrics, test_scores = evaluate_partition(
        pipeline, testing, threshold)
    return pipeline, threshold, validation_metrics, test_metrics, per_capture_test_metrics, test_scores


def train(manifest, output, cap=100000):
    output = Path(output)
    if output.exists() and any((output / name).exists() for name in ("model.joblib", "evaluation.json", "model.tmp")):
        raise FileExistsError("Output contains an existing model/evaluation; choose a new versioned folder")
    rows, sources = load_manifest(manifest, cap)
    source_provenances = {entry["provenance"] for entry in sources if "provenance" in entry}
    if len(source_provenances) > 1:
        raise ValueError("Do not mix official IoT-23 and labelled lab captures in one model")
    source_provenance = next(iter(source_provenances), "iot23_official")
    model_provenance = "real_lab_capture" if source_provenance == "labelled_lab_capture" else "real_iot23"
    untouched = {split: [r for r in rows if r["split"] == split]
                 for split in ("train", "validation", "test")}
    for split, values in untouched.items():
        if len({r["capture"] for r in values}) < 2 or set(r["label"] for r in values) != {"normal", "attack"}:
            raise ValueError(f"{split} needs multiple independent captures and both binary classes")

    # This is retained only as a secondary diagnostic. Primary training and
    # threshold selection must use the untouched capture-disjoint partitions.
    filtered, exclusions = exact_feature_filter(untouched)
    filtered_ready = all(
        len({r["capture"] for r in filtered[split]}) >= 2
        and set(r["label"] for r in filtered[split]) == {"normal", "attack"}
        for split in ("train", "validation", "test"))

    pipeline, threshold, validation_metrics, test_metrics, per_capture_test_metrics, _ = fit_evaluate(untouched)
    secondary = {
        "status": "unavailable",
        "reason": "Exact-feature exclusion removed a class or independent capture from a split.",
        "split_rows": {split: len(values) for split, values in filtered.items()},
        "overlap_excluded": exclusions,
    }
    if filtered_ready:
        _, secondary_threshold, secondary_validation, secondary_test, secondary_per_capture, _ = fit_evaluate(filtered)
        secondary = {
            "status": "available",
            "method": "historical_exact_feature_exclusion",
            "threshold": secondary_threshold,
            "validation_metrics": secondary_validation,
            "test_metrics": secondary_test,
            "per_capture_test_metrics": secondary_per_capture,
            "split_rows": {split: len(values) for split, values in filtered.items()},
            "class_distributions": {split: class_distribution([r["label"] for r in values])
                                    for split, values in filtered.items()},
            "overlap_excluded": exclusions,
        }
    latency = []
    xt = matrix([r["features"] for r in untouched["test"]])
    for row in xt[:100]:
        before = time.perf_counter()
        pipeline.predict_proba(np.array([row], dtype=object))
        latency.append((time.perf_counter() - before) * 1000)
    report = dict(test_metrics)
    report.update(report_version=("real-lab-evaluation-v1" if model_provenance == "real_lab_capture"
                                  else "real-iot23-evaluation-v2"),
        evaluation_population="untouched_capture_disjoint",
        threshold_selection_population="untouched_validation",
        schema=SCHEMA, provenance=model_provenance, task="binary", features=FEATURES,
        threshold=threshold, validation_metrics=validation_metrics,
        split_rows={k: len(v) for k, v in untouched.items()},
        class_distributions={k: class_distribution([r["label"] for r in v])
                             for k, v in untouched.items()},
        capture_counts_before_after=capture_counts(untouched, filtered),
        per_capture_test_metrics=per_capture_test_metrics,
        secondary_filtered_evaluation=secondary,
        sources=sources, inference_ms_p50=float(np.median(latency)), inference_ms_p95=float(np.percentile(latency, 95)),
        scope=("Labelled private lab captures; registered-device scope only; live promotion requires independent validation"
               if model_provenance == "real_lab_capture" else "Official IoT-23 subset; no ESP32/live validation"),
        live_validated=False,
        trained_at=time.time(), sklearn_version=sklearn.__version__)
    report["eligible"] = report["recall"] >= .8 and report["false_positive_rate"] <= .05 and validation_metrics["recall"] >= .8
    output.mkdir(parents=True, exist_ok=True)
    artifact = dict(model=pipeline, schema=SCHEMA, features=FEATURES, provenance=model_provenance,
                    sklearn_version=sklearn.__version__, report=report)
    joblib.dump(artifact, output / "model.tmp")
    (output / "model.tmp").replace(output / "model.joblib")
    (output / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("runtime/iot23-model-experiment"))
    parser.add_argument("--max-per-capture", type=int, default=100000)
    args = parser.parse_args()
    if not 100 <= args.max_per_capture <= 500000:
        parser.error("max-per-capture must be 100..500000")
    print(json.dumps(train(args.manifest, args.output, args.max_per_capture), indent=2))
