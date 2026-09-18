"""Pre-install gate tests: real subprocess runs of scripts/scr-gate/scr_gate.py.

All fixtures are synthetic, local, benign (demo-site/gate-fixtures). These tests invoke
the gate exactly as a developer would, capturing TRUE exit codes and raw stdout. No
original lab package is ever executed; the only script ever run is the approved benign
fixture's own postinstall (and only in the approved path, after the tamper-evident
approval record is written and verified on read).

Run from the repo root:
  ./.venv/Scripts/python.exe -m pytest scripts/scr-gate/test_scr_gate.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
PY = next((c for c in (REPO / ".venv" / "Scripts" / "python.exe", REPO / ".venv" / "bin" / "python")
           if c.exists()), Path(sys.executable))
GATE = REPO / "scripts" / "scr-gate" / "scr_gate.py"
ALLOWLIST = REPO / "scripts" / "scr-gate" / "allowlist.json"
PROJECTS = REPO / "demo-site" / "gate-fixtures" / "projects"


def run_gate(project: str, tmp_path: Path, extra_args: list[str] | None = None,
             allowlist: Path | None = None):
    target = tmp_path / "target"
    cmd = [
        str(PY), str(GATE), "install",
        "--project", str(PROJECTS / project),
        "--allowlist", str(allowlist or ALLOWLIST),
        "--target", str(target),
    ]
    if extra_args:
        cmd += extra_args
    res = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                         errors="replace")
    return res, target


def test_blocked_path_leaves_no_marker(tmp_path):
    """The core claim: the blocked case runs NO lifecycle hook and writes NO marker."""
    res, target = run_gate("blocked", tmp_path)
    assert res.returncode != 0, f"gate should block, stdout:\n{res.stdout}"
    # fail-closed / block decision recorded
    report = json.loads(res.stdout)
    assert report["action"] in ("block", "hold"), report["action"]
    assert report["unapproved"], "chain-pkg-evil must be flagged as unapproved"
    # the malicious fixture's marker must NOT exist
    assert not list(target.rglob("MARKER_EVIL.txt")), \
        "blocked path must not have run the unapproved postinstall"
    # no install ran at all in the target (scripts disabled everywhere, nothing installed)
    assert not (target / "node_modules").exists(), "no node_modules in a blocked install"
    assert not list(target.rglob("MARKER_GOOD.txt"))


def test_approved_path_marker_only_after_tamper_evident_approval(tmp_path):
    """The positive path: the benign marker appears, but only AFTER a tamper-evident,
    identity-bound approval record exists (verified on read before the install)."""
    res, target = run_gate("approved", tmp_path)
    assert res.returncode == 0, f"gate should allow, stdout:\n{res.stdout}\nstderr:\n{res.stderr}"
    # tamper-evident approval record written before the marker
    rec = target / ".chainshield-gate-approval.json"
    assert rec.exists(), "identity-bound approval record must be written"
    data = json.loads(rec.read_text())
    assert data["action"] == "allow"
    assert data["composite_identity_sha256"], "approval must be bound to a composite identity"
    assert data["policy_version"]  # policy version is part of the decision seam
    # the marker appears only now, after approval
    markers = list(target.rglob("MARKER_GOOD.txt"))
    assert markers, "approved path must have run the harmless marker"
    assert "APPROVED" in markers[0].read_text()
    # the NOT-approved evil marker must not appear even in the approved project
    assert not list(target.rglob("MARKER_EVIL.txt"))


def test_approved_decision_only_writes_no_marker(tmp_path):
    """--no-final-install: decision is ALLOW but no marker runs (proves ordering)."""
    res, target = run_gate("approved", tmp_path, extra_args=["--no-final-install"])
    assert res.returncode == 0
    assert not list(target.rglob("MARKER_GOOD.txt"))
    assert not (target / "node_modules").exists()


def test_approval_bound_to_bytes_not_replayable_name(tmp_path):
    """Replaying the APPROVED name with DIFFERENT bytes must block (no name-only replay)."""
    res, target = run_gate("tampered", tmp_path)
    assert res.returncode != 0, "same name, different bytes must be refused"
    report = json.loads(res.stdout)
    assert report["unapproved"], "tampered artifact must be flagged"
    issues = str(report["unapproved"])
    assert "bytes-mismatch" in issues, issues
    assert not list(target.rglob("MARKER_GOOD.txt"))
    assert not list(target.rglob("MARKER_EVIL.txt"))


def test_no_lockfile_is_refused(tmp_path):
    """Unpinned install (no package-lock.json) is explicitly unsupported => fail-closed."""
    res, target = run_gate("no-lock", tmp_path)
    assert res.returncode != 0
    assert not list(target.rglob("MARKER_GOOD.txt"))


def test_missing_allowlist_fails_closed(tmp_path):
    """A mandatory check that cannot be completed (missing allowlist) must NOT proceed."""
    res, target = run_gate("approved", tmp_path, allowlist=tmp_path / "does-not-exist.json")
    assert res.returncode != 0
    report = json.loads(res.stdout)
    assert report.get("fail_closed_error"), report
    assert not list(target.rglob("MARKER_GOOD.txt"))


# ── pure classification unit tests (no network, proves the refusal logic) ─────

def _classify(resolved):
    from scr_gate import classify_resolved
    return classify_resolved(resolved)


def test_unsupported_schemes_are_classified_for_refusal():
    # git/http/https/bare-registry are ALL refused (never pretended to be covered);
    # only a local file: tarball is a supported tracer input
    for s in [
        "git+https://github.com/a/b.git",
        "https://registry.npmjs.org/x",
        "http://localhost:4873/x",
        "registry.npmjs.org/x",
    ]:
        assert _classify(s) != "file:", f"{s} must not be treated as supported"
    assert _classify("") == "empty"
    assert _classify("file:../tarballs/x.tgz") == "file:"


# ── D1 regression: unrecognised / unparseable lockfile format must FAIL CLOSED ─
# Regression: an approval record being written for a project whose only
# dependency was the non-allowlisted chain-pkg-evil, because a v1 lockfile (which uses
# "dependencies", not "packages") parsed to ZERO artifacts -> rule_score 0.0 -> ALLOW.
# "zero artifacts resolved" is a FAULT, never "nothing to check".

def test_v1_lockfile_decision_layer_fails_closed(monkeypatch):
    """D1 core: with npm resolution neutralised, a v1 lockfile must still REFUSE.

    RED on the pre-fix gate: it returned exit 0 / action=allow for a tree it never
    inspected (the unjustified-ALLOW path the review found).
    """
    import scr_gate
    monkeypatch.setattr(scr_gate, "resolve_phase", lambda *a, **k: None)
    code, report = scr_gate.run_gate(PROJECTS / "v1-format", ALLOWLIST, None)
    assert code != 0, f"D1: v1 lockfile must fail closed at the decision layer, got {code}: {report}"
    assert report.get("action") == "block", report
    err = str(report.get("fail_closed_error", ""))
    assert "lockfileVersion" in err or "unrecognised" in err or "format" in err, err


def test_v1_lockfile_end_to_end_refused_no_approval_record(tmp_path):
    """D1 end-to-end: the v1 project is refused for a FORMAT reason, and NO approval
    record is written (the review saw an allow record for exactly this shape)."""
    res, target = run_gate("v1-format", tmp_path)
    assert res.returncode != 0, f"v1 lockfile must refuse, stdout:\n{res.stdout}"
    report = json.loads(res.stdout)
    err = str(report.get("fail_closed_error", ""))
    assert "lockfileVersion" in err or "unrecognised" in err or "format" in err, \
        f"refusal must name the unrecognised lockfile format (not just npm failing): {err}"
    assert not (target / ".chainshield-gate-approval.json").exists(), \
        "a refused (unrecognised-format) project must write NO approval record"
    assert not (target / "node_modules").exists()
    assert not list(target.rglob("MARKER_EVIL.txt"))
    assert not list(target.rglob("MARKER_GOOD.txt"))


def test_unrecognised_or_empty_lockfile_format_refused_unit():
    """Pure unit: validate_lockfile refuses v1 (no 'packages') and an empty packages map."""
    import scr_gate
    for bad in (
        {"lockfileVersion": 1, "dependencies": {"chain-pkg-evil": {}}},
        {"lockfileVersion": 3, "packages": {}},
        {"lockfileVersion": 3, "packages": {"node_modules/x": {}}},  # no root entry
        {"packages": {"": {}}},                                     # no lockfileVersion
    ):
        with pytest.raises(scr_gate.GateRefusal):
            scr_gate.validate_lockfile(bad)


def test_declared_dependency_without_resolved_artifact_is_a_fault():
    """A declared dependency with no resolved artifact => fail closed (incomplete set)."""
    import scr_gate
    pkg = {"dependencies": {"chain-pkg-good": "file:x.tgz", "chain-pkg-absent": "file:y.tgz"}}
    resolved = [{"name": "chain-pkg-good"}]
    missing = scr_gate.missing_declared_dependencies(pkg, resolved)
    assert missing == {"chain-pkg-absent"}, missing


# ── D2: the approval record is tamper-EVIDENT (not "immutable") ───────────────

def test_approval_record_is_tamper_evident(tmp_path):
    """The record carries a self-hash; a tampered record is detected on read."""
    import scr_gate
    target = tmp_path / "target"
    scr_gate.write_approval_record(
        target, "deadbeef" * 8,
        {"action": "allow", "verdict": "allow", "policy_version": scr_gate.GATE_POLICY_VERSION})
    rec_path = target / ".chainshield-gate-approval.json"
    rec = json.loads(rec_path.read_text())
    assert rec["self_sha256"], "record must carry a self-hash over its identity fields"
    # untampered record verifies
    assert scr_gate.verify_approval_record(target, "deadbeef" * 8)["action"] == "allow"
    # tamper one identity field -> detection on read
    rec["action"] = "block"
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    with pytest.raises(scr_gate.GateRefusal):
        scr_gate.verify_approval_record(target, "deadbeef" * 8)


def test_approval_record_refuses_overwrite(tmp_path):
    """The record is written once (O_EXCL); an existing record is never overwritten."""
    import scr_gate
    target = tmp_path / "target"
    verdict = {"action": "allow", "verdict": "allow", "policy_version": "v"}
    scr_gate.write_approval_record(target, "a" * 64, verdict)
    with pytest.raises(scr_gate.GateRefusal):
        scr_gate.write_approval_record(target, "b" * 64, verdict)


# ── D5: post-unpack verification (narrowed TOCTOU; stated, not closed) ────────

def test_post_unpack_verification_is_recorded(tmp_path):
    """The approved path verifies the UNPACKED tree against the approved tarball and
    records the result (files verified + re-checked tarball sha256)."""
    res, target = run_gate("approved", tmp_path)
    assert res.returncode == 0, f"approved path should allow:\n{res.stdout}\n{res.stderr}"
    vpath = target / ".chainshield-gate-verification.json"
    assert vpath.exists(), "post-unpack verification result must be recorded"
    v = json.loads(vpath.read_text())
    assert v["packages"], v
    pkg = v["packages"][0]
    assert pkg["name"] == "chain-pkg-good"
    assert pkg["files_verified"] >= 1
    assert pkg["tarball_sha256_rechecked"] == pkg["approved_sha256"]
    # the benign marker still appears (verification runs after the install, before/around
    # the gate's own hook invocation) and no evil marker ever does
    assert list(target.rglob("MARKER_GOOD.txt"))
    assert not list(target.rglob("MARKER_EVIL.txt"))


def test_post_unpack_verification_detects_content_mismatch(tmp_path):
    """Non-tautology check: post-unpack verification REFUSES a corrupted installed tree,
    i.e. the step is not vacuous."""
    import scr_gate
    res, target = run_gate("approved", tmp_path)
    assert res.returncode == 0, res.stdout
    approved = json.loads(res.stdout)["artifacts"]
    # corrupt a file that IS present in the approved tarball
    victim = target / "node_modules" / "chain-pkg-good" / "index.js"
    assert victim.is_file()
    victim.write_text("// tampered after unpack\n", encoding="utf-8")
    with pytest.raises(scr_gate.GateRefusal):
        scr_gate.verify_post_install(target, approved, PROJECTS / "approved")

