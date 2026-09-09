import hashlib
import json
from pathlib import Path
import shutil
import unittest
import uuid
from unittest.mock import patch

from backend.config import ROOT
from backend.database import Store
from ml.train import metrics, train
from scripts.export_evidence import export_evidence


def feature_row(seed):
    return {
        "duration": float(seed),
        "orig_bytes": float(seed + 1),
        "resp_bytes": float(seed + 2),
        "orig_pkts": float(seed + 3),
        "orig_ip_bytes": float(seed + 4),
        "resp_pkts": float(seed + 5),
        "resp_ip_bytes": float(seed + 6),
        "missed_bytes": float(seed + 7),
        "proto": "tcp",
        "service": "http",
        "conn_state": "SF",
    }


class EvaluationMetricsTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / ".test-work" / ("evaluation-" + str(uuid.uuid4()))
        self.root.mkdir(parents=True)

    def tearDown(self):
        if self.root.resolve().is_relative_to((ROOT / ".test-work").resolve()):
            shutil.rmtree(self.root)

    def test_single_class_metrics_leave_auc_and_missing_denominators_undefined(self):
        normal = metrics(["normal", "normal"], [0.1, 0.9], 0.5)
        attack = metrics(["attack", "attack"], [0.1, 0.9], 0.5)

        self.assertIsNone(normal["roc_auc"])
        self.assertIsNone(normal["pr_auc_average_precision"])
        self.assertFalse(normal["auc_defined"])
        self.assertIsNone(normal["false_negative_rate"])
        self.assertIsNone(attack["roc_auc"])
        self.assertIsNone(attack["pr_auc_average_precision"])
        self.assertIsNone(attack["false_positive_rate"])
        self.assertEqual(attack["false_negative_rate"], 0.5)

    def test_report_contains_split_distributions_and_capture_metrics(self):
        rows = []
        seed = 1
        for split in ("train", "validation", "test"):
            for label, capture in (("normal", f"{split}-normal"),
                                   ("attack", f"{split}-attack")):
                for _ in range(4):
                    rows.append({"features": feature_row(seed), "label": label,
                                 "capture": capture, "split": split})
                    seed += 1

        with patch("ml.train.load_manifest", return_value=(rows, [])):
            report = train(self.root / "fixture.json", self.root / "model")

        self.assertEqual(report["class_distributions"]["test"]["normal"], 4)
        self.assertEqual(report["class_distributions"]["test"]["attack"], 4)
        self.assertEqual(report["report_version"], "real-iot23-evaluation-v2")
        self.assertEqual(report["evaluation_population"], "untouched_capture_disjoint")
        self.assertEqual(report["threshold_selection_population"], "untouched_validation")
        self.assertEqual(report["capture_counts_before_after"]["test"]["test-normal"]["before"]["total"], 4)
        self.assertEqual(report["capture_counts_before_after"]["test"]["test-normal"]
                         ["after_exact_feature_exclusion"]["total"], 4)
        self.assertIn("false_negative_rate", report)
        self.assertEqual(set(report["per_capture_test_metrics"]),
                         {"test-normal", "test-attack"})
        self.assertIsNone(report["per_capture_test_metrics"]["test-normal"]["roc_auc"])
        self.assertIsNone(report["per_capture_test_metrics"]["test-attack"]["roc_auc"])


class EvidenceExportTests(unittest.TestCase):
    def setUp(self):
        self.root = ROOT / ".test-work" / ("evidence-" + str(uuid.uuid4()))
        self.root.mkdir(parents=True)

    def tearDown(self):
        if self.root.resolve().is_relative_to((ROOT / ".test-work").resolve()):
            shutil.rmtree(self.root)

    def make_database(self, path):
        store = Store(path)
        try:
            store.put("traffic", {"run_id": "run-a", "origin": "live",
                                   "prediction": "benign", "ground_truth": None,
                                   "model_sha256": "model-hash",
                                   "schema": "zeek-conn-v1", "model_scope": "fixture"})
            store.put("traffic", {"run_id": "run-a", "origin": "dataset",
                                   "prediction": "malicious", "ground_truth": "attack"})
            store.put("traffic", {"run_id": "run-b", "origin": "live",
                                   "prediction": "malicious", "ground_truth": None})
            store.put("alerts", {"run_id": "run-a", "origin": "live",
                                  "prediction": "malicious"})
            store.put("blocks", {"run_id": "run-a", "origin": "live",
                                  "status": "blocked", "source_ip": "198.51.100.10",
                                  "verified": True, "verification": "verified"})
            store.put("blocks", {"run_id": "run-a", "origin": "live",
                                  "status": "dry_run", "source_ip": "198.51.100.11",
                                  "scope": "host", "verified": False,
                                  "verification": "not_performed"})
            store.put("events", {"run_id": "run-a", "origin": "live",
                                  "kind": "ATTACK_DETECTED"})
        finally:
            store.close()

    def test_export_filters_and_hashes_without_declaring_verification(self):
        root = self.root
        database = root / "runtime.sqlite3"
        source = root / "conn.log"
        source.write_text('{"uid":"fixture"}\n', encoding="utf-8")
        self.make_database(database)
        before = database.read_bytes()

        manifest = export_evidence(database, "run-a", "live", root / "evidence", source)

        self.assertEqual(before, database.read_bytes())
        self.assertEqual(manifest["run_id"], "run-a")
        self.assertEqual(manifest["origin"], "live")
        self.assertEqual(manifest["report_sha256"],
                         next(item["sha256"] for item in manifest["artifacts"]
                              if item["name"] == "report.json"))
        self.assertEqual(manifest["provenance_sha256"],
                         next(item["sha256"] for item in manifest["artifacts"]
                              if item["name"] == "provenance.json"))
        self.assertEqual(manifest["source_conn_log"]["sha256"],
                         hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(manifest["model_provenance"]["status"], "complete")
        self.assertEqual(manifest["model_provenance"]["model_sha256"], ["model-hash"])
        self.assertEqual({item["name"] for item in manifest["missing_artifacts"]},
                         {"pcap", "parquet", "verified_blocks"})

        predictions = json.loads((root / "evidence" / "predictions.json").read_text())
        self.assertEqual(len(predictions["rows"]), 1)
        self.assertEqual(predictions["rows"][0]["origin"], "live")
        firewall = json.loads((root / "evidence" / "firewall.json").read_text())
        self.assertEqual(len(firewall["observed_blocks"]), 2)
        self.assertEqual(firewall["verification"]["status"], "not_performed")
        self.assertFalse(firewall["verification"]["verified"])
        legacy = next(row for row in firewall["observed_blocks"] if row["status"] == "blocked")
        self.assertFalse(legacy["verified"])
        self.assertEqual(legacy["verification"], "not_performed")
        self.assertEqual(legacy["status_semantics"], "legacy_unverified")
        self.assertNotIn("stored_verified", legacy)
        self.assertNotIn("stored_verification", legacy)
        self.assertFalse(firewall["exporter_actions"]["firewall"])

    def test_synthetic_origin_is_rejected_before_output_creation(self):
        root = self.root
        database = root / "runtime.sqlite3"
        self.make_database(database)

        with self.assertRaisesRegex(ValueError, "synthetic/demo"):
            export_evidence(database, "run-a", "demo", root / "evidence")
        self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
