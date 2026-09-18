import unittest

from app.attacks import typosquatting as ts


class TestLevenshtein(unittest.TestCase):
    def test_identical(self) -> None:
        self.assertEqual(ts.levenshtein_distance("acme", "acme"), 0)

    def test_one_substitution(self) -> None:
        self.assertEqual(ts.levenshtein_distance("ledger", "leder"), 1)


class TestAnalyzeNameRisk(unittest.TestCase):
    def test_typo_high_risk(self) -> None:
        a = ts.analyze_name_risk("acme-leder", "acme-ledger")
        self.assertEqual(a.distance, 1)
        self.assertEqual(a.risk_tier, "high")


class TestSimulateInstall(unittest.TestCase):
    def test_trusted_package(self) -> None:
        r = ts.simulate_install("acme-ledger")
        self.assertEqual(r.outcome, "trusted_install")
        self.assertFalse(r.attacker_success)
        self.assertTrue(r.record is not None and r.record.trusted)

    def test_typosquat_package(self) -> None:
        r = ts.simulate_install("acme-leder")
        self.assertEqual(r.outcome, "typosquat_install")
        self.assertTrue(r.attacker_success)
        self.assertTrue(r.record is not None and not r.record.trusted)

    def test_unknown_not_found(self) -> None:
        r = ts.simulate_install("totally-unknown-pkg")
        self.assertEqual(r.outcome, "not_found")
        self.assertFalse(r.attacker_success)

    def test_case_insensitive_lookup(self) -> None:
        r = ts.simulate_install("Acme-Leder")
        self.assertEqual(r.outcome, "typosquat_install")


if __name__ == "__main__":
    unittest.main()
