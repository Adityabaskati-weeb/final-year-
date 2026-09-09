import unittest

from scripts.build_credibility_report import build_report
from scripts.fetch_iot_audit_model import ARTIFACT_SHA256, ARTIFACT_URL, UPSTREAM_COMMIT


class CredibilityReportTests(unittest.TestCase):
    def test_external_reference_is_pinned_and_never_response_eligible(self):
        report = build_report()
        external = report["models"]["external_iot_audit"]
        self.assertEqual(external["expected_sha256"], ARTIFACT_SHA256)
        self.assertIn(UPSTREAM_COMMIT, external["source_url"])
        self.assertIn(ARTIFACT_URL, external["source_url"])
        self.assertFalse(external["status"]["response_eligible"])

    def test_claim_ledger_keeps_gateway_and_family_claims_explicit(self):
        report = build_report()
        claims = {claim["id"]: claim for claim in report["claims"]}
        self.assertIn(claims["attack_family_classification"]["status"], {"not_promoted", "promoted"})
        self.assertEqual(claims["gateway_enforcement"]["status"], "not_verified")
        self.assertTrue(claims["gateway_enforcement"]["not_supported"])


if __name__ == "__main__":
    unittest.main()
