import unittest

from app.attacks import dependency_confusion as dc


class TestDependencyConfusionCore(unittest.TestCase):
    def test_internal_style_name(self) -> None:
        self.assertTrue(dc.is_internal_style_name("corp-internal-ledger-api"))
        self.assertFalse(dc.is_internal_style_name("requests"))

    def test_safe_internal_default_policy(self) -> None:
        r = dc.simulate_resolution("corp-internal-ledger-api", "*")
        self.assertEqual(r.outcome, "safe_internal")
        self.assertFalse(r.attacker_success)
        self.assertTrue(r.resolved is not None and r.resolved.source == "internal")

    def test_confused_public_when_internal_not_preferred(self) -> None:
        policy = dc.ResolverPolicy(
            prefer_internal=False,
            allow_public_fallback_for_internal_names=True,
            enforce_internal_namespace_block=False,
        )
        r = dc.simulate_resolution("corp-internal-ledger-api", "*", policy=policy)
        self.assertEqual(r.outcome, "confused_public")
        self.assertTrue(r.attacker_success)
        self.assertTrue(r.resolved is not None and r.resolved.source == "public")

    def test_block_unknown_internal_name_from_public(self) -> None:
        # Present only in public registry if inserted ad-hoc
        public_only_name = "corp-internal-not-real"
        dc.PUBLIC_REGISTRY[public_only_name] = dc.RegistryPackage(
            name=public_only_name,
            version="9.9.9",
            source="public",
            trusted=False,
            publisher="attacker",
            simulated_effect="demo",
        )
        try:
            r = dc.simulate_resolution(public_only_name, "*")
            self.assertEqual(r.outcome, "blocked_policy")
            self.assertFalse(r.attacker_success)
        finally:
            del dc.PUBLIC_REGISTRY[public_only_name]

    def test_scan_manifest(self) -> None:
        manifest = {
            "react": "^18.3.1",
            "corp-internal-ledger-api": "1.0.0",
        }
        result = dc.scan_manifest_for_dependency_confusion(manifest)
        self.assertEqual(result["scanned"], 2)
        self.assertEqual(result["internal_style_dependencies"], 1)
        self.assertEqual(result["findings_count"], 1)
        self.assertEqual(result["findings"][0]["outcome"], "safe_internal")


if __name__ == "__main__":
    unittest.main()

