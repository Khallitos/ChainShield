"""Trusted-baseline tests (typosquatting and dependency confusion).

Behavioural tests only: no source-string greps, no tautologies, no xfail.

Covered:
  * unseen typo variants flagged: transposition, doubled char, homoglyph/confusable,
    hyphen insertion/removal, scope change (@scope/name vs name)
  * benign-but-similar legitimate names NOT over-flagged
  * exact name and exact scoped name -> not-a-typo / "none"
  * a name absent from the supplied baseline handled explicitly (documented semantics)
  * the `critical` homoglyph tier is REACHABLE with correct ordering
  * dependency confusion: a large version alone -> insufficient evidence, never a finding
  * no demo-registry authority in the decision path (DEMO_REGISTRY is fixture data only)
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.attacks import dependency_confusion as dc
from app.attacks import typosquatting as ts
from app.policy.trusted_baseline import (
    TrustedBaseline,
    load_trusted_baseline,
)
from app.services import trust_graph as tg

REPO = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO / "data" / "trusted" / "baseline.json"

FLAGGED = {"low", "medium", "high", "critical"}

# Cyrillic small a (U+0430), NFKC/casefold does NOT fold it to ASCII 'a'.
CYRILLIC_A = "\u0430"


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ── loader / authority ────────────────────────────────────────────────────────

class TestTrustedBaselineLoader:
    def test_loads_supplied_baseline_and_is_read_only(self):
        before = _sha256(BASELINE_PATH)
        bl = load_trusted_baseline()
        assert isinstance(bl, TrustedBaseline)
        assert bl.baseline_id == "default"
        assert "react" in bl.canonical_names
        assert "@babel/core" in bl.canonical_names
        assert len(bl.canonical_names) >= 100  # 113 in the supplied file
        # using it must never rewrite the frozen data file
        assert _sha256(BASELINE_PATH) == before

    def test_scoped_and_case_insensitive_lookup(self):
        bl = load_trusted_baseline()
        assert bl.is_canonical("react")
        assert bl.is_canonical("REACT")
        assert bl.is_canonical("@babel/core")
        assert not bl.is_canonical("react-dommm")
        assert bl.canonical_for("@Babel/Core") == "@babel/core"

    def test_accepts_a_supplied_path_not_hardcoded_to_one_file(self, tmp_path):
        custom = tmp_path / "baseline.json"
        custom.write_text(
            json.dumps(
                {
                    "baseline_id": "custom",
                    "trusted_packages": {"acme-widget": {"version": "1.0.0", "trusted": True}},
                    "canonical_names": ["acme-widget", "@acme/ledger"],
                    "internal_namespace_patterns": ["^acme-"],
                    "registry_policy": {},
                }
            ),
            encoding="utf-8",
        )
        bl = load_trusted_baseline(custom)
        assert bl.baseline_id == "custom"
        assert bl.is_canonical("acme-widget")
        assert bl.is_canonical("@acme/ledger")


# ── unseen typo variants against the supplied baseline ────────────────────────

class TestUnseenVariantsFlagged:
    @pytest.mark.parametrize(
        "candidate,expected_canon",
        [
            ("raect", "react"),        # transposition
            ("reacct", "react"),       # doubled character
            ("reactdom", "react-dom"),  # hyphen removal
            ("react--dom", "react-dom"),  # hyphen insertion
        ],
    )
    def test_variant_flagged_against_baseline(self, candidate, expected_canon):
        bl = load_trusted_baseline()
        a = ts.analyze_against_baseline(candidate, bl)
        assert a.matched_canonical == expected_canon
        assert a.risk_tier in FLAGGED, (candidate, a)

    def test_homoglyph_confusable_reaches_critical(self):
        a = ts.analyze_name_risk("re" + CYRILLIC_A + "ct", "react")
        assert a.risk_tier == "critical"
        assert a.confidence >= 0.9
        assert a.distance >= 1  # raw names really do differ

    def test_pure_ascii_never_critical(self):
        assert ts.analyze_name_risk("reactt", "react").risk_tier != "critical"

    def test_scope_change_flagged(self):
        bl = load_trusted_baseline()
        # unscoped name that IS the basename of a scoped canon (scope removed)
        a = ts.analyze_against_baseline("core", bl)
        assert a.risk_tier in FLAGGED
        assert a.matched_canonical == "@babel/core"
        # scoped form of an unscoped canon (scope added)
        b = ts.analyze_against_baseline("@evil/react", bl)
        assert b.risk_tier in FLAGGED
        assert b.matched_canonical == "react"

    def test_different_scopes_are_not_cross_matched(self):
        bl = load_trusted_baseline()
        # '@evil/core' is a DIFFERENT scoped package, not a scope change of '@babel/core'
        c = ts.analyze_against_baseline("@evil/core", bl)
        assert c.risk_tier == "none"


# ── benign / exact / absent semantics ─────────────────────────────────────────

class TestNotOverFlagged:
    @pytest.mark.parametrize("benign", ["lodash", "express", "left-pad", "@types/node", "electron"])
    def test_benign_similar_names_not_flagged(self, benign):
        bl = load_trusted_baseline()
        a = ts.analyze_against_baseline(benign, bl)
        assert a.risk_tier == "none", (benign, a)
        assert a.matched_canonical is None
        assert a.in_baseline is False


class TestExactNamesAreNone:
    def test_exact_unscoped(self):
        bl = load_trusted_baseline()
        a = ts.analyze_against_baseline("react", bl)
        assert a.risk_tier == "none"
        assert a.in_baseline is True
        assert a.distance == 0

    def test_exact_scoped(self):
        bl = load_trusted_baseline()
        a = ts.analyze_against_baseline("@babel/core", bl)
        assert a.risk_tier == "none"
        assert a.in_baseline is True
        assert a.distance == 0

    def test_pairwise_exact_is_none(self):
        assert ts.analyze_name_risk("react", "react").risk_tier == "none"
        assert ts.analyze_name_risk("@babel/core", "@babel/core").risk_tier == "none"


class TestAbsentFromBaseline:
    def test_absent_is_explicitly_not_malicious(self):
        bl = load_trusted_baseline()
        a = ts.analyze_against_baseline("brand-new-pkg-2026", bl)
        assert a.risk_tier == "none"
        assert a.in_baseline is False
        assert a.matched_canonical is None
        lowered = a.note.lower()
        assert "not" in lowered and ("malicious" in lowered or "unknown" in lowered)

    def test_absent_produces_no_manifest_finding(self):
        result = ts.scan_manifest({"brand-new-pkg-2026": "1.0.0"})
        assert result.findings == []
        assert result.risk_summary.get("none") == 0  # nothing claimed either way


# ── decision path uses the baseline, NOT the demo registry ────────────────────

class TestNoDemoRegistryAuthority:
    def test_demo_squatter_flagged_only_by_explicit_policy_denylist(self):
        """``training-leder`` is a baseline member, so baseline membership alone must not accuse it.

        The lab verdict comes from the explicit policy denylist
        (``backend/app/policy/declared_squatters.json``), reported with
        ``detection_basis == "policy_denylist"`` so it is never confused with a similarity
        inference. Lockfile depth is not used (see TestNearTwinIsNeverAccusedOnDepth).
        """
        result = ts.scan_manifest({"training-leder": "1.0.0"})
        hits = [x for x in result.findings if x["package"] == "training-leder"]
        assert len(hits) == 1, result.findings
        assert hits[0]["canonical"] == "training-ledger"
        assert hits[0]["detection_basis"] == "policy_denylist"
        assert hits[0]["risk_tier"] == "high"
        lowered = hits[0]["note"].lower()
        assert "policy" in lowered and "denylist" in lowered

    def test_root_declared_near_twin_is_not_flagged(self):
        # The supplied baseline mechanically captured BOTH members of the pair. Only the
        # one declared in the deeper (nested victim) lockfile is the suspect.
        result = ts.scan_manifest({"training-ledger": "1.0.0"})
        assert [f for f in result.findings if f["package"] == "training-ledger"] == []

    def test_demo_pair_without_baseline_canon_is_not_flagged(self):
        # 'acme-leder' is a DEMO_REGISTRY malicious entry but its canonical
        # 'acme-ledger' is NOT in the supplied baseline -> it must not be flagged
        # just because it appears in the demo list.
        result = ts.scan_manifest({"acme-leder": "1.0.0"})
        assert result.findings == []
        # ...while the demo fixture narrative itself is still intact
        sim = ts.simulate_install("acme-leder")
        assert sim.outcome == "typosquat_install"

    def test_only_the_declared_squatter_is_flagged_across_the_demo_list(self):
        # Every DEMO_REGISTRY key in one manifest: the only flagged name is the one with an
        # explicit policy-denylist entry; trusted names and names absent from the baseline are not.
        manifest = {
            "training-leder": "1.0.0",
            "training-ledger": "1.0.0",
            "acme-leder": "1.0.0",
            "acme-ledger": "1.0.0",
        }
        result = ts.scan_manifest(manifest)
        assert [f["package"] for f in result.findings] == ["training-leder"]
        assert result.findings[0]["detection_basis"] == "policy_denylist"

    def test_scan_manifest_uses_the_SUPPLIED_baseline(self, tmp_path):
        custom = tmp_path / "baseline.json"
        custom.write_text(
            json.dumps(
                {
                    "baseline_id": "custom",
                    "trusted_packages": {
                        "acme-widget": {"version": "1.0.0", "trusted": True},
                    },
                    "canonical_names": ["acme-widget"],
                    "internal_namespace_patterns": ["^acme-"],
                    "registry_policy": {},
                }
            ),
            encoding="utf-8",
        )
        bl = load_trusted_baseline(custom)
        result = ts.scan_manifest({"acme-widgett": "1.0.0"}, baseline=bl)
        assert [f["package"] for f in result.findings] == ["acme-widgett"]
        assert result.findings[0]["canonical"] == "acme-widget"
        # the same name is not flagged against the repository baseline
        assert ts.scan_manifest({"acme-widgett": "1.0.0"}).findings == []


# ── dependency confusion requires evidence ────────────────────────────────────

class TestDependencyConfusionEvidence:
    def test_large_version_alone_is_insufficient_evidence(self):
        a = dc.assess_dependency_confusion(
            "corp-internal-shiny-new", "99.0.0", evidence=dc.ConfusionEvidence()
        )
        assert a["outcome"] == dc.INSUFFICIENT_EVIDENCE
        assert a["severity"] == "none"
        assert a["attacker_success"] is False

    def test_high_version_alone_yields_no_finding(self):
        result = dc.scan_manifest_for_dependency_confusion(
            {"corp-internal-not-in-any-registry": "99.0.0"}
        )
        assert result["findings"] == []
        assert result["insufficient_evidence_count"] == 1

    def test_confirmed_only_with_full_evidence(self):
        ev = dc.ConfusionEvidence(
            private_name_declared=True,
            allowed_registry_policy=True,
            resolution_evidence=True,
        )
        # a misconfigured resolver (public fallback allowed) is what makes confusion real
        misconfigured = dc.ResolverPolicy(
            prefer_internal=False,
            allow_public_fallback_for_internal_names=True,
            enforce_internal_namespace_block=False,
        )
        a = dc.assess_dependency_confusion(
            "corp-internal-ledger-api", "9.9.9", evidence=ev, policy=misconfigured
        )
        assert a["outcome"] == "confirmed_confusion"
        assert a["attacker_success"] is True

    def test_full_evidence_with_strict_policy_is_safe_internal(self):
        ev = dc.ConfusionEvidence(
            private_name_declared=True,
            allowed_registry_policy=True,
            resolution_evidence=True,
        )
        a = dc.assess_dependency_confusion("corp-internal-ledger-api", "9.9.9", evidence=ev)
        assert a["outcome"] == "safe_internal"
        assert a["attacker_success"] is False

    def test_partial_evidence_still_insufficient(self):
        ev = dc.ConfusionEvidence(private_name_declared=True, resolution_evidence=True)
        a = dc.assess_dependency_confusion("corp-internal-ledger-api", "9.9.9", evidence=ev)
        assert a["outcome"] == dc.INSUFFICIENT_EVIDENCE
        assert a["attacker_success"] is False

    def test_version_recorded_as_advisory_only(self):
        ev = dc.ConfusionEvidence(
            private_name_declared=True,
            allowed_registry_policy=True,
            resolution_evidence=True,
        )
        misconfigured = dc.ResolverPolicy(
            prefer_internal=False,
            allow_public_fallback_for_internal_names=True,
            enforce_internal_namespace_block=False,
        )
        a = dc.assess_dependency_confusion(
            "corp-internal-ledger-api", "9.9.9", evidence=ev, policy=misconfigured
        )
        assert a["version_signal"] in (True, False)  # recorded, never the sole basis
        assert a["outcome"] == "confirmed_confusion"

    def test_low_version_with_full_evidence_is_decided_by_evidence_not_version(self):
        ev = dc.ConfusionEvidence(
            private_name_declared=True,
            allowed_registry_policy=True,
            resolution_evidence=True,
        )
        misconfigured = dc.ResolverPolicy(
            prefer_internal=False,
            allow_public_fallback_for_internal_names=True,
            enforce_internal_namespace_block=False,
        )
        a = dc.assess_dependency_confusion(
            "corp-internal-ledger-api", "1.0.0", evidence=ev, policy=misconfigured
        )
        assert a["version_signal"] is False
        assert a["outcome"] == "confirmed_confusion"


# ── lockfile depth is NOT a legitimacy signal ─────────────────────────────────
#
# An explicit supplied baseline, so the test does not depend on the data file. Both members of
# each pair are legitimate sibling packages; only the declaring lockfile depth differs (a
# sub-project / monorepo layout). Neither may be flagged.

_NEAR_TWIN_BASELINE = {
    "baseline_id": "near-twin",
    "trusted_packages": {
        "@myco/lib": {"version": "1.0.0", "trusted": True, "from_lockfile": "package-lock.json"},
        "@myco/libr": {
            "version": "1.0.0",
            "trusted": True,
            "from_lockfile": "packages/sub-project/package-lock.json",
        },
        "ui-lib": {"version": "2.0.0", "trusted": True, "from_lockfile": "package-lock.json"},
        "ui-libx": {
            "version": "1.0.0",
            "trusted": True,
            "from_lockfile": "apps/web/vendor/deep/package-lock.json",
        },
    },
    "canonical_names": ["@myco/lib", "@myco/libr", "ui-lib", "ui-libx"],
    "internal_namespace_patterns": [],
    "registry_policy": {},
}


def _write_baseline(tmp_path, payload) -> TrustedBaseline:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return load_trusted_baseline(p)


class TestNearTwinIsNeverAccusedOnDepth:
    @pytest.mark.parametrize("name", ["@myco/lib", "@myco/libr", "ui-lib", "ui-libx"])
    def test_exact_baseline_member_is_not_flagged(self, tmp_path, name):
        bl = _write_baseline(tmp_path, _NEAR_TWIN_BASELINE)
        a = ts.analyze_against_baseline(name, bl)
        assert a.in_baseline is True
        assert a.risk_tier == "none", (name, a)
        assert a.is_flagged is False
        assert a.matched_canonical == name  # reports itself, not the near-twin

    def test_deeper_declared_legit_near_twin_pair_is_never_accused(self, tmp_path):
        # Reviewer repro: the deeper-declared legit scoped sibling and the deep monorepo twin used
        # to come back `high`. They are baseline members, so no finding may be produced.
        bl = _write_baseline(tmp_path, _NEAR_TWIN_BASELINE)
        assert ts.analyze_against_baseline("@myco/libr", bl).risk_tier == "none"
        assert ts.analyze_against_baseline("ui-libx", bl).risk_tier == "none"
        assert ts.scan_manifest({"@myco/libr": "1.0.0"}, bl).findings == []
        assert ts.scan_manifest({"ui-libx": "1.0.0"}, bl).findings == []

    def test_near_twin_surfaced_as_non_escalating_advisory(self, tmp_path):
        bl = _write_baseline(tmp_path, _NEAR_TWIN_BASELINE)
        a = ts.analyze_against_baseline("@myco/libr", bl)
        assert a.risk_tier == "none" and a.is_flagged is False
        assert a.advisory, "the ambiguity must still be visible to a human"
        lowered = a.advisory.lower()
        assert "advisory" in lowered and "not" in lowered
        # The advisory is distinct from a finding and from the risk tier: it does not move the
        # summary and it never becomes a finding.
        res = ts.scan_manifest({"@myco/libr": "1.0.0"}, bl)
        assert res.findings == []
        assert res.risk_summary.get("high", 0) == 0
        assert any(x["package"] == "@myco/libr" for x in res.advisories)

    def test_no_frozen_baseline_canonical_is_flagged_on_depth_grounds(self):
        # Invariant for the shipped baseline: an EXACT member is never accused.
        bl = load_trusted_baseline()
        flagged = [n for n in bl.canonical_names if ts.analyze_against_baseline(n, bl).is_flagged]
        assert flagged == [], flagged

    def test_outcome_is_independent_of_which_side_is_deeper(self, tmp_path):
        # Depth must not influence the result: invert the pair and confirm the same trust verdict.
        inverted = json.loads(json.dumps(_NEAR_TWIN_BASELINE))
        inverted["trusted_packages"]["@myco/lib"]["from_lockfile"] = "deep/nested/package-lock.json"
        inverted["trusted_packages"]["@myco/libr"]["from_lockfile"] = "package-lock.json"
        bl = _write_baseline(tmp_path, inverted)
        assert ts.analyze_against_baseline("@myco/libr", bl).risk_tier == "none"
        assert ts.analyze_against_baseline("@myco/lib", bl).risk_tier == "none"

    def test_stated_limitation_equal_or_shallower_capture_is_a_false_negative(self, tmp_path):
        # Honest, documented limitation (see typosquatting docstring): a squatter captured at EQUAL
        # or SHALLOWER depth is NOT detected by baseline-near-twin logic at all. This test pins the
        # limitation so it is never silently assumed away; detection of such a name must come from a
        # distance/denylist signal, not from provenance.
        bl = _write_baseline(tmp_path, {
            "baseline_id": "equal-depth",
            "trusted_packages": {
                "foobar": {"version": "1.0.0", "trusted": True, "from_lockfile": "package-lock.json"},
                "fooba": {"version": "1.0.0", "trusted": True, "from_lockfile": "package-lock.json"},
            },
            "canonical_names": ["foobar", "fooba"],
            "internal_namespace_patterns": [],
            "registry_policy": {},
        })
        # Both are exact baseline members at equal depth -> both trusted; the squatter among them
        # (if any) is a false negative of this mechanism, which the docstring states plainly.
        assert ts.analyze_against_baseline("fooba", bl).is_flagged is False
        assert ts.scan_manifest({"fooba": "1.0.0"}, bl).findings == []


# ── the demo name's verdict is an explicit, auditable policy input ──

DENYLIST_PATH = REPO / "backend" / "app" / "policy" / "declared_squatters.json"


class TestDemoVerdictIsExplicitPolicy:
    def test_policy_input_lives_in_the_revised_tree_with_declared_provenance(self):
        assert DENYLIST_PATH.is_file()
        payload = json.loads(DENYLIST_PATH.read_text(encoding="utf-8"))
        entry = payload["entries"]["training-leder"]
        assert entry["canonical"] == "training-ledger"
        assert entry["provenance"].strip(), "an auditable policy entry must state where it came from"

    def test_baseline_membership_alone_does_not_accuse_the_demo_name(self):
        # Separation of concerns: the name IS a baseline member, so the baseline scorer returns an
        # exact, trusted, non-escalated result for it (only an advisory surfaces the near-twin)...
        a = ts.analyze_against_baseline("training-leder")
        assert a.in_baseline is True
        assert a.risk_tier == "none"
        assert a.is_flagged is False
        assert a.advisory
        # ...and the trusted leg is clean (no finding, no advisory).
        clean = ts.analyze_against_baseline("training-ledger")
        assert clean.risk_tier == "none" and clean.is_flagged is False

    def test_policy_hit_is_labelled_and_keeps_the_demo_escalation(self):
        res = ts.scan_manifest({"training-leder": "1.0.0"})
        f = [x for x in res.findings if x["package"] == "training-leder"]
        assert len(f) == 1, res.findings
        f = f[0]
        assert f["detection_basis"] == "policy_denylist"
        assert f["risk_tier"] == "high"
        assert f["canonical"] == "training-ledger"
        assert isinstance(f["distance"], int) and f["distance"] >= 1
        assert res.risk_summary.get("high") == 1

    def test_trusted_leg_is_not_a_denylist_entry(self):
        payload = json.loads(DENYLIST_PATH.read_text(encoding="utf-8"))
        assert "training-ledger" not in payload["entries"]
        assert ts.scan_manifest({"training-ledger": "1.0.0"}).findings == []


# ── the reachable `critical` tier is consistent across trust_graph ──

CYRILLIC_E = "\u0435"
# Cyrillic small e + Cyrillic small a: two raw edits from ASCII "react", identical confusable
# skeleton. (A one-edit homoglyph already drifted via the min_edit==1 clause, so two edits is the
# case that isolates the missing `critical` tier.)
TWO_EDIT_HOMOGLYPH = "r" + CYRILLIC_E + CYRILLIC_A + "ct"


class TestCriticalTierConsistency:
    def test_two_edit_homoglyph_is_critical_everywhere(self):
        name = TWO_EDIT_HOMOGLYPH
        assert ts.levenshtein_distance(name, "react") == 2  # genuinely two raw edits
        assert ts.analyze_name_risk(name, "react").risk_tier == "critical"
        assert ts.scan_manifest({name: "1.0.0"}).risk_summary.get("critical") == 1
        drift = tg.check_package_drift(name, "1.0.0")
        assert drift["typosquat_risk_tier"] == "critical"
        assert drift["exact_trusted_match"] is False
        assert drift["baseline_drift"] is True


# ── no invented trusted version for names without provenance ──

class TestVersionGapUsesOnlyRealProvenance:
    def test_internal_style_name_without_a_trusted_version_has_no_gap_signal(self):
        # `corp-internal-...` matches the internal namespace but is NOT an exact trusted match, so
        # there is no known trusted version to compare against. The gap is unknowable and must be
        # reported as 0.0 (unknown), never computed against the invented constant "1.4.2".
        d = tg.check_package_drift("corp-internal-unknown-thing", "99.0.0")
        assert d["internal_namespace"] is True
        assert d["exact_trusted_match"] is False
        assert d["version_gap_score"] == 0.0
        # Detection is NOT lost: the internal-namespace clause still flags the drift.
        assert d["baseline_drift"] is True

    def test_exact_internal_name_uses_its_own_recorded_version(self):
        bl = tg.get_trusted_graph()
        recorded = str(bl["trusted_packages"]["corp-internal-ledger-api"]["version"])
        d = tg.check_package_drift("corp-internal-ledger-api", "99.0.0")
        assert d["exact_trusted_match"] is True
        # compared against the baseline's own recorded provenance value, not a magic constant
        assert d["version_gap_score"] == tg.version_gap_score("99.0.0", recorded)
        assert d["version_gap_score"] > 0.0

    def test_magic_constant_is_not_used_as_a_fallback(self):
        d = tg.check_package_drift("corp-internal-brand-new", "99.0.0")
        # the old code returned version_gap_score("99.0.0", "1.4.2") == 0.95 here
        assert d["version_gap_score"] != tg.version_gap_score("99.0.0", "1.4.2")
        assert d["version_gap_score"] == 0.0


# ── the API contract carries the additive fields ────────────────

class TestScanEndpointContract:
    def test_scan_endpoint_serialises_policy_basis_in_siem_event(self):
        from fastapi.testclient import TestClient

        from app.main import app

        resp = TestClient(app).post(
            "/v1/scan/typosquatting",
            json={"dependencies": {"training-leder": "1.0.0"}, "source": "p2-fix1"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["findings_count"] == 1
        assert body["risk_summary"]["high"] == 1
        event = body["siem_events"][0]
        assert event["severity"] == "high"
        assert event["detection_basis"] == "policy_denylist"
        assert "policy denylist hit" in event["note"].lower()

    def test_scan_endpoint_serialises_critical_homoglyph(self):
        from fastapi.testclient import TestClient

        from app.main import app

        resp = TestClient(app).post(
            "/v1/scan/typosquatting",
            json={"dependencies": {TWO_EDIT_HOMOGLYPH: "1.0.0"}, "source": "p2-fix1"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["risk_summary"]["critical"] == 1
        assert body["siem_events"][0]["detection_basis"] == "baseline_similarity"
