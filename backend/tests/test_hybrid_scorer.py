"""Tests for hybrid scorer."""
import unittest

from app.schemas.scan_report import Decision, DefenseMode
from app.services.hybrid_scorer import score_manifest_hybrid


class TestHybridScorer(unittest.TestCase):
    def test_typosquat_blocked_hybrid(self):
        score, decision, reasons, drift, _ = score_manifest_hybrid(
            {"training-leder": "1.0.0"},
            DefenseMode.HYBRID,
        )
        self.assertGreaterEqual(score, 0.6)
        self.assertIn(decision, (Decision.BLOCK, Decision.WARN))
        self.assertTrue(drift or reasons)

    def test_trusted_allowed(self):
        score, decision, _, _, _ = score_manifest_hybrid(
            {"training-ledger": "1.0.0"},
            DefenseMode.HYBRID,
        )
        self.assertLess(score, 0.85)
        self.assertEqual(decision, Decision.ALLOW)

    def test_unblocked_always_allow(self):
        _, decision, _, _, _ = score_manifest_hybrid(
            {"training-leder": "1.0.0"},
            DefenseMode.UNBLOCKED,
        )
        self.assertEqual(decision, Decision.ALLOW)


if __name__ == "__main__":
    unittest.main()
