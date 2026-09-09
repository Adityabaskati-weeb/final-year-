import hashlib
import unittest
from pathlib import Path

from backend.iot_audit_candidate import ARTIFACT_SHA256, FEATURES, IoTAuditCandidate, build_features


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "runtime/iot-audit-pretrained/binary_lightgbm.joblib"


class IoTAuditCandidateTests(unittest.TestCase):
    def setUp(self):
        self.record = {
            "duration": 0.25,
            "orig_bytes": 120,
            "resp_bytes": 80,
            "orig_pkts": 3,
            "orig_ip_bytes": 240,
            "resp_pkts": 2,
            "resp_ip_bytes": 160,
            "missed_bytes": 0,
            "proto": "tcp",
            "service": "-",
            "conn_state": "SF",
        }

    def test_feature_contract_is_stable(self):
        frame = build_features(self.record)
        self.assertEqual(list(frame.columns), FEATURES)
        self.assertEqual(frame.shape, (1, 13))
        self.assertAlmostEqual(float(frame.iloc[0]["bytes_total"]), 4. * 0 + 5.303304908, places=5)

    @unittest.skipUnless(ARTIFACT.is_file(), "downloaded candidate artifact is not present")
    def test_artifact_hash_and_pipeline_contract(self):
        actual = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
        self.assertEqual(actual, ARTIFACT_SHA256)
        candidate = IoTAuditCandidate(ARTIFACT)
        self.assertTrue(candidate.status()["ready"])
        self.assertEqual(candidate.status()["classes"], ["normal", "attack"])
        result = candidate.predict(self.record)
        self.assertIn(result["prediction"], {"benign", "malicious"})
        self.assertIsNotNone(result["attack_probability"])

    def test_missing_directional_fields_are_rejected(self):
        broken = dict(self.record)
        broken["orig_pkts"] = "-"
        with self.assertRaisesRegex(ValueError, "missing Zeek fields"):
            build_features(broken)


if __name__ == "__main__":
    unittest.main()
