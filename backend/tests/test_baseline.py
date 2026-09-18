"""Tests for trust baseline builder."""
import unittest

from app.services.baseline_builder import build_baseline, matches_internal_namespace, parse_npm_lockfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "demo-site" / "package-lock.json"


class TestBaselineBuilder(unittest.TestCase):
    def test_parse_lockfile_has_training_ledger(self):
        if not LOCK.is_file():
            self.skipTest("demo-site lockfile missing")
        pkgs = parse_npm_lockfile(LOCK)
        self.assertIn("training-ledger", pkgs)

    def test_build_baseline(self):
        baseline = build_baseline()
        self.assertIn("trusted_packages", baseline)
        self.assertIn("training-ledger", baseline["trusted_packages"])

    def test_internal_namespace(self):
        self.assertTrue(matches_internal_namespace("corp-internal-ledger-api", [r"^corp-internal-"]))


if __name__ == "__main__":
    unittest.main()
