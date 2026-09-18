#!/usr/bin/env python3
"""npm pre-install gate (synthetic benign fixtures only).

PROOF OF MECHANISM, NOT PRODUCTION ENFORCEMENT.

This wrapper demonstrates that a *developer-independent* npm boundary is achievable:
it resolves the dependency tree with lifecycle scripts DISABLED, inspects the resolved
artifact identities, evaluates them through the decision contract
(backend/app/policy/decision_contract.py), and only then lets the install proceed or
blocks it BEFORE any lifecycle hook could run. It is a wrapper OUTSIDE the package, so it
does not depend on any package-owned hook cooperating.

  USAGE
    python scr_gate.py resolve --project <dir> --allowlist <path> [--log <file>]
    python scr_gate.py install --project <dir> --allowlist <path> --target <dir> \
            [--no-final-install]

  SUPPORTED PATH (the ONLY one)
    A project dir containing a PINNED package-lock.json whose dependencies are local
    `file:` tarballs under the tracer fixture tarball dir, each resolving to a real file
    whose name+version+sha256-of-bytes matches an entry in the allowlist. All offline.

  FAIL-CLOSED (refuse, exit 2), unrecognised/incomplete input is a FAULT, never "ok"
    * package-lock.json whose `lockfileVersion` is not 2 or 3       -> REFUSE
      (e.g. lockfileVersion 1 uses `dependencies`, not `packages`)
    * `packages` missing / empty / no root "" entry                 -> REFUSE
    * ZERO resolved artifacts parsed                                -> REFUSE
      ("nothing resolved" is a fault; it is NEVER "nothing to check")
    * a declared dependency (deps/devDeps/optionalDeps in package.json) with no
      resolved artifact                                             -> REFUSE
    * missing lockfile (unpinned install), missing allowlist, non-empty allowlist
      required, malformed JSON, missing/unreadable resolved tarball -> REFUSE
    * any git:// / http(s):// / bare-registry scheme, or empty `resolved` -> REFUSE
      (the ONLY supported scheme is a local `file:` tarball)
    * any `file:` tarball whose name+version+bytes do not match the allowlist -> BLOCK
    * an unsafe package name (path separator / `..`)                -> REFUSE

  NOT REFUSED (there is no code path for these, they are RESIDUAL BYPASSES, see below)
    * `npm rebuild`            -> NOT seen by this tracer; a direct `npm rebuild` bypasses
    * `npm install`            -> NOT seen by this tracer; a direct `npm install` bypasses
    * `--ignore-scripts=false` on third-party code -> no such experiment is handled here
    Listing these as "refused" would imply enforcement that does not exist. It is not.

  GATE FLOW (fail-closed at every step)
    1. Validate inputs + lockfile FORMAT. Any error => REFUSE (exit != 0), nothing
       installed. Unrecognised lockfile format / zero artifacts => REFUSE.
    2. RESOLVE with scripts DISABLED: `npm ci --dry-run --ignore-scripts --offline`
       in the project dir (npm computes the resolved tree itself; scripts cannot run).
    3. Classify every resolved dependency scheme; unsupported => REFUSE.
    4. Compute per-artifact identity: sha256 of each resolved tarball's bytes.
    5. Build a composite identity = sha256(lockfile bytes + sorted name->sha256
       + allowlist bytes + gate policy version). Approval is bound to this, not to a name.
    6. DECIDE via backend/app/policy/decision_contract.decide() with the gate's
       rules-only policy. The policy is built with ml_required=False, so a missing ML
       model is NOT itself a fail-closed trigger here: this tracer loads no model and
       the net fail-closed guarantee comes from the MANDATORY violation raised for any
       unapproved/unknown/mismatched artifact, plus the catch-all on any unexpected error.
       Any unapproved artifact => BLOCK. Any exception => fail-closed BLOCK.
    7. BLOCKED => print reason, exit 3. NO target install, NO marker.
    8. ALLOWED => write a TAMPER-EVIDENT identity-bound approval record (self-hash over
       its identity fields; written once with O_EXCL; NOT immutable / NOT tamper-proof
       it is a normal writable file, but a tampered record is DETECTED on read), VERIFY it
       on read, then (unless --no-final-install) perform the final install in --target
       with scripts DISABLED (`npm ci --ignore-scripts`), then run POST-UNPACK
       VERIFICATION (re-hash the approved tarball and compare every file in the approved
       tarball's content manifest against the installed tree, byte for byte), then invoke
       ONLY the approved package's own benign postinstall. The harmless marker therefore
       appears ONLY after the approval record. This gate-as-authority invocation is a
       proof-of-mechanism detail; a production gate would let npm run the hook for an
       allowScripts-approved, registry-integrity-verified package.

  RESIDUAL BYPASSES
    * This wrapper is NOT wired into npm anywhere. A direct `npm ci|install|rebuild`, a
      developer simply not using the wrapper, and yarn / pnpm / bun all bypass it entirely.
    * A lockfile EDIT changes the composite identity and is caught; a lockfile FORMAT
      change is now refused (fail-closed), both inside the wrapper's supported path only.
    * npm 12's own default blocking of dependency lifecycle scripts (`allowScripts`) is a
      SEPARATE, coincidental layer. It is NOT this gate's achievement and NOT an
      enforcement authority this deliverable controls; it is absent on npm <= 10.
    * TOCTOU between hashing tarball bytes and npm unpacking them is NARROWED (post-unpack
      verification + npm's lockfile integrity), NOT closed.

  SAFETY
    No real malware. No original lab hooks/collectors/exfil scripts are ever executed.
    No network. Offline only. Only synthetic benign fixtures created for this tracer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# ── repo / backend discovery ──────────────────────────────────────────────────
REPO = Path(__file__).resolve().parents[2]          # ChainShield-revised
BACKEND = REPO / "backend"
FIXTURES = REPO / "demo-site" / "gate-fixtures"
TARBALL_DIR = FIXTURES / "tarballs"

sys.path.insert(0, str(BACKEND))
from app.policy import decision_contract as dc  # noqa: E402

GATE_POLICY_VERSION = "gate-rules-0.1.0"
BLOCK_EXIT = 3
ERROR_EXIT = 2
OK_EXIT = 0

# lockfile formats this tracer can inspect. A version outside this set (notably v1,
# whose dependency set lives under "dependencies", not "packages") is REFUSED, never
# treated as "no packages => nothing to check".
SUPPORTED_LOCKFILE_VERSIONS = (2, 3)

APPROVAL_RECORD_NAME = ".chainshield-gate-approval.json"
VERIFICATION_RECORD_NAME = ".chainshield-gate-verification.json"

# a safe npm package name: optional @scope/ prefix, no path separators, no '..'
_PKG_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$")

# schemes that a supported install may reference; anything else is refused
ALLOWED_SCHEMES = {"file:"}
REFUSED_SCHEME_HINTS = {"git:", "git+", "http:", "https:", "git@", "ssh:"}


class GateRefusal(Exception):
    """Fail-closed refusal of an unsupported input or failed mandatory check."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def npm_bin() -> str:
    """npm executable name (npm.cmd on Windows so subprocess can find it)."""
    return "npm.cmd" if os.name == "nt" else "npm"


def run_capture(cmd, cwd: Path, logfile: Path | None) -> tuple[int, str]:
    """Run a command, capture raw stdout+stderr, return (TRUE exit code, combined text).

    Never pipes through a shell that masks the real exit code.
    """
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    text = proc.stdout or ""
    if logfile is not None:
        with open(logfile, "a", encoding="utf-8") as f:
            f.write(f"$ {' '.join(cmd)}\n")
            f.write(text if text.endswith("\n") else text + "\n")
            f.write(f"[exit={proc.returncode}]\n")
    return proc.returncode, text


def load_json(path: Path, what: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:  # noqa: BLE001 - fail-closed
        raise GateRefusal(f"cannot parse {what} {path}: {exc}")


def _name_from_node(node: str) -> str:
    """Derive a package name from a lockfile 'packages' path key.

    Handles the root '', nested 'a/node_modules/b' and scoped '@scope/name' forms.
    """
    n = node
    # take the segment after the LAST 'node_modules/'
    if "node_modules/" in n:
        n = n.split("node_modules/")[-1]
    n = n.strip("/")
    segs = n.split("/")
    if segs and segs[0].startswith("@") and len(segs) >= 2:
        return segs[0] + "/" + segs[1]
    return segs[-1] if segs else n


def validate_package_name(name: str) -> None:
    """Refuse a lockfile-derived name that is not a safe single package-name path
    component (no path separators, no '..'), closing the path-injection shape."""
    if not isinstance(name, str) or not _PKG_NAME_RE.match(name):
        raise GateRefusal(f"unsafe package name {name!r} in lockfile; refusing")
    if name in (".", "..") or ".." in name.split("/") or "\\" in name or "\x00" in name:
        raise GateRefusal(f"unsafe package name {name!r} in lockfile; refusing")


def validate_lockfile(lock: dict) -> None:
    """Fail CLOSED unless the lockfile is a format this tracer can fully inspect.

    An unrecognised format (lockfileVersion not in SUPPORTED_LOCKFILE_VERSIONS, e.g. v1
    whose dependency set is under 'dependencies'), or a missing/empty 'packages' map, or
    a missing root ('') entry, is REFUSED, it is never treated as "nothing to check".
    """
    if not isinstance(lock, dict):
        raise GateRefusal("lockfile root is not a JSON object; refusing (fail-closed)")
    version = lock.get("lockfileVersion")
    if version not in SUPPORTED_LOCKFILE_VERSIONS:
        raise GateRefusal(
            "unrecognised lockfile format: lockfileVersion="
            f"{version!r} (supported: {list(SUPPORTED_LOCKFILE_VERSIONS)}); "
            "refusing (fail-closed), cannot inspect this dependency set")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise GateRefusal(
            "lockfile 'packages' is missing or empty; refusing (fail-closed), "
            "an empty resolution is a fault, not 'nothing to check'")
    if "" not in packages:
        raise GateRefusal(
            "lockfile 'packages' has no root ('') entry; refusing (fail-closed)")


def parse_lockfile(lock: dict, project_dir: Path) -> list[dict]:
    """Extract resolved packages from a validated v2/v3 lockfile 'packages' map,
    skipping the root '' key. Assumes validate_lockfile() has already been called."""
    packages = lock.get("packages") or {}
    resolved: list[dict] = []
    for node, meta in packages.items():
        if node == "":
            continue  # project root
        if not isinstance(meta, dict):
            raise GateRefusal(f"lockfile entry {node!r} is not an object; refusing (fail-closed)")
        name = meta.get("name") or _name_from_node(node)
        validate_package_name(name)
        resolved.append(
            {
                "node": node,
                "name": name,
                "version": meta.get("version"),
                "resolved": meta.get("resolved"),
                "integrity": meta.get("integrity"),
                "has_install_script": bool(meta.get("hasInstallScript")),
            }
        )
    return resolved


def declared_dependency_names(pkg: dict) -> set[str]:
    """Names declared in package.json dependencies/devDependencies/optionalDependencies."""
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        d = pkg.get(key)
        if isinstance(d, dict):
            names.update(str(k) for k in d.keys())
    return names


def missing_declared_dependencies(pkg: dict, resolved: list[dict]) -> set[str]:
    """Declared dependencies that resolved to NO artifact (an incomplete set => a fault)."""
    resolved_names = {r.get("name") for r in resolved}
    return {n for n in declared_dependency_names(pkg) if n not in resolved_names}



def classify_resolved(resolved: str) -> str:
    """Return a scheme token for a lockfile 'resolved' value."""
    r = (resolved or "").strip()
    if not r:
        return "empty"
    for hint in REFUSED_SCHEME_HINTS:
        if r.startswith(hint):
            return "refused"
    if r.startswith("file:"):
        return "file:"
    return "unknown"


def locate_tarball(resolved: str, project_dir: Path) -> Path:
    """Resolve a `file:` tarball path relative to the project dir. Must exist."""
    rel = resolved[len("file:"):]
    # strip a possible leading '/'-style or drive handling; npm writes POSIX-ish rel
    p = (project_dir / rel).resolve()
    return p


def artifact_sha_for(resolved: str, project_dir: Path) -> tuple[str, Path]:
    """Compute sha256 of the on-disk tarball bytes. Raises GateRefusal if missing."""
    p = locate_tarball(resolved, project_dir)
    if not p.is_file():
        raise GateRefusal(f"resolved tarball not found on disk: {resolved} -> {p}")
    return sha256_file(p), p


def build_gate_policy() -> dc.Policy:
    """Rules-only gate policy built on the accepted contract's Policy type.

    No ML model is loaded in this tracer, so `ml_required=False`: a missing model is NOT
    a fail-closed trigger and MUST NOT be described as one. With ml_required=False the
    contract's `_fuse` falls back to the rules-only score (`rule_score`). Fail-closed for
    this gate comes from the MANDATORY violation raised for any unapproved artifact
    (`mandatory_action=Action.BLOCK`) and from the catch-all `except Exception` in
    run_gate: not from the model.

    Note honestly: if this policy ever saw zero artifacts with no mandatory violation, the
    rules-only score would be 0.0 => ALLOW. That is exactly why run_gate REFUSES a
    zero-artifact / unrecognised-format lockfile BEFORE it builds evidence, so the decision
    contract is never asked to bless an empty resolution.
    """
    return dc.Policy(
        policy_version=GATE_POLICY_VERSION,
        rule_weight=1.0,          # rules-only: score == rule score
        ml_weight=0.0,
        block_threshold=0.5,      # any rule finding >= 0.5 blocks
        warn_threshold=0.25,
        trusted_cap=None,
        ml_required=False,
        model_missing_verdict=dc.VerdictLevel.HOLD,
        model_missing_action=dc.Action.BLOCK,
        mandatory_action=dc.Action.BLOCK,
        description=(
            "Rules-only gate policy: identity/allowlist check via the shared "
            "decision contract; no ML model loaded (ml_required=False, so a missing model "
            "is not itself fail-closed here); fail-closed comes from the mandatory "
            "violation raised for any unapproved artifact."
        ),
    )


def build_evidence(verdict: str, composite_identity: str, unapproved: list[dict],
                   findings: list) -> dc.Evidence:
    """Build Evidence for the decision contract.

    provenance='install' (an ALLOWED_PROVENANCE). Approved => low rule score, no
    mandatory violation. Any unapproved artifact => mandatory approved_registry_violation
    (fail-closed BLOCK that ML/cap cannot downgrade).
    """
    mandatory = []
    if unapproved:
        # report the first violating registry/source token
        reg = unapproved[0].get("resolved") or unapproved[0].get("name") or "unknown"
        mandatory.append(
            dc.MandatoryViolation.create(
                code="approved_registry_violation",
                provenance="install",
                registry=str(reg)[:200],
            )
        )
    return dc.Evidence(
        rule_score=1.0 if unapproved else 0.0,
        ml_score=None,
        model_status=dc.ModelStatus.ABSENT,  # no ML model in this tracer
        evidence_source="install",
        findings=tuple(findings),
        baseline_signals={
            "artifact_identity": composite_identity,
            "exact_trusted_match": not bool(unapproved),
        },
        mandatory_violations=tuple(mandatory),
    )


def _approval_identity_material(composite_identity, action, verdict, policy_version,
                                approved_at) -> dict:
    """The identity fields that the approval record's self-hash covers."""
    return {
        "composite_identity_sha256": composite_identity,
        "action": action,
        "verdict": verdict,
        "policy_version": policy_version,
        "approved_at_utc": approved_at,
    }


def write_approval_record(target_dir: Path, composite_identity: str, verdict: dict) -> Path:
    """Write a TAMPER-EVIDENT identity-bound approval record BEFORE the marker may run.

    NOT immutable and NOT tamper-proof: it is a normal writable file. It is made
    tamper-EVIDENT: a self-hash covers its identity fields, it is written once
    (``O_CREAT|O_EXCL``) so an existing record is never silently overwritten, and
    ``verify_approval_record`` recomputes the self-hash and checks the composite identity
    on read (the final install refuses on any mismatch).
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    approved_at = datetime.now(timezone.utc).isoformat()
    identity = _approval_identity_material(
        composite_identity, verdict.get("action"), verdict.get("verdict"),
        verdict.get("policy_version"), approved_at)
    record = {
        "kind": "gate-approval",
        "scope": "proof of mechanism, not production enforcement",
        "tamper_evidence": ("self_sha256 over the identity fields below; verified on read. "
                            "NOT immutable / NOT tamper-proof."),
        **identity,
        "approved_packages": "only artifacts whose name+version+bytes are in the allowlist",
    }
    record["self_sha256"] = sha256_bytes(
        json.dumps(identity, sort_keys=True).encode("utf-8"))
    out = target_dir / APPROVAL_RECORD_NAME
    data = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    try:
        fd = os.open(str(out), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        raise GateRefusal(f"approval record already exists, refusing to overwrite: {out}")
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return out


def verify_approval_record(target_dir: Path, expected_composite: str) -> dict:
    """Re-read and verify the approval record: recompute its self-hash and compare the
    composite identity. Any mismatch (tampered record, wrong identity) => GateRefusal."""
    path = target_dir / APPROVAL_RECORD_NAME
    if not path.is_file():
        raise GateRefusal(f"approval record missing on read: {path}")
    rec = load_json(path, "approval record")
    identity = _approval_identity_material(
        rec.get("composite_identity_sha256"), rec.get("action"), rec.get("verdict"),
        rec.get("policy_version"), rec.get("approved_at_utc"))
    expect = sha256_bytes(json.dumps(identity, sort_keys=True).encode("utf-8"))
    if rec.get("self_sha256") != expect:
        raise GateRefusal("approval record self-hash mismatch (record was tampered); refusing")
    if expected_composite and rec.get("composite_identity_sha256") != expected_composite:
        raise GateRefusal("approval record identity does not match the decided identity; refusing")
    return rec


def tarball_content_manifest(tarball: Path) -> dict[str, str]:
    """Map 'path relative to the package root' -> sha256 of that file's bytes, read from
    the approved tarball itself. Used for post-unpack verification. No extraction to disk,
    no execution."""
    manifest: dict[str, str] = {}
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            rel = member.name
            if rel.startswith("package/"):
                rel = rel[len("package/"):]
            f = tf.extractfile(member)
            if f is None:
                continue
            manifest[rel] = sha256_bytes(f.read())
    return manifest


def verify_post_install(target_dir: Path, approved: list[dict], project_dir: Path) -> list[dict]:
    """POST-UNPACK verification (narrows, does not close, TOCTOU).

    For each approved artifact: re-hash the resolved tarball on disk (must still equal the
    approved bytes) and compare every file in that tarball's content manifest against the
    installed tree, byte for byte. Mismatch => GateRefusal (fail-closed). Residual: the
    tarball is still read more than once, so a swap that is undone between reads is not
    detectable here.
    """
    results: list[dict] = []
    for pkg in approved:
        name = pkg.get("name")
        validate_package_name(name)
        tarball = locate_tarball(pkg.get("resolved") or "", project_dir)
        if not tarball.is_file():
            raise GateRefusal(f"post-unpack: approved tarball vanished for {name}: {tarball}")
        rechecked = sha256_file(tarball)
        approved_sha = pkg.get("sha256")
        if rechecked != approved_sha:
            raise GateRefusal(
                f"post-unpack: tarball bytes changed after approval for {name} "
                f"({rechecked} != {approved_sha}); refusing")
        manifest = tarball_content_manifest(tarball)
        root = target_dir / "node_modules" / name
        mismatches: list[str] = []
        for rel, sha in manifest.items():
            installed = root / rel
            if not installed.is_file():
                mismatches.append(f"missing:{rel}")
            elif sha256_file(installed) != sha:
                mismatches.append(f"content-mismatch:{rel}")
        if mismatches:
            raise GateRefusal(
                f"post-unpack: installed tree for {name} does not match the approved "
                f"tarball: {mismatches[:5]}; refusing")
        results.append({
            "name": name,
            "files_verified": len(manifest),
            "approved_sha256": approved_sha,
            "tarball_sha256_rechecked": rechecked,
            "verified": True,
        })
    return results


def write_verification_record(target_dir: Path, results: list[dict]) -> Path:
    """Record the post-unpack verification outcome alongside the approval record."""
    out = target_dir / VERIFICATION_RECORD_NAME
    payload = {
        "kind": "gate-post-unpack-verification",
        "scope": "narrows, but does not close, the TOCTOU window",
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "packages": results,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out


def _rewrite_lockfile_for_target(lock: dict, project_dir: Path) -> dict:
    """Return a copy of the lockfile with `file:` resolved paths made ABSOLUTE so a
    copied project in a fresh --target can still locate the immutable fixture tarballs."""
    packages = lock.get("packages", {})
    new_packages = {}
    for node, meta in packages.items():
        m = dict(meta)
        res = m.get("resolved")
        if isinstance(res, str) and res.startswith("file:"):
            p = locate_tarball(res, project_dir)
            m["resolved"] = "file:" + p.as_posix()
        new_packages[node] = m
    root = new_packages.get("")
    if isinstance(root, dict):
        root = dict(root)
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            if isinstance(root.get(key), dict):
                root[key] = _absolute_file_specs(root[key], project_dir)
        new_packages[""] = root
    new_lock = dict(lock)
    new_lock["packages"] = new_packages
    return new_lock


def _absolute_file_specs(deps: dict, project_dir: Path) -> dict:
    """`file:` dependency specs resolved against the project dir, so a copied manifest in a
    fresh --target still points at the fixture tarballs."""
    out = {}
    for name, spec in deps.items():
        if isinstance(spec, str) and spec.startswith("file:"):
            tail = Path(spec[len("file:"):])
            spec = "file:" + (tail if tail.is_absolute() else (project_dir / tail).resolve()).as_posix()
        out[name] = spec
    return out


def find_postinstall(pkg_root: Path) -> Path | None:
    """Return path to the approved package's postinstall script, if any."""
    for name in ("postinstall.mjs", "postinstall.js", "postinstall.cjs"):
        cand = pkg_root / name
        if cand.is_file():
            return cand
    return None


def run_final_install(project_dir: Path, target_dir: Path, logfile: Path | None) -> None:
    """Approved path, step 1: install into --target with scripts DISABLED.

    The package's own lifecycle scripts are NOT run here; they are invoked only by
    invoke_approved_hooks() after post-unpack verification has passed.
    """
    # 1. copy manifest + rewritten lockfile into target
    target_dir.mkdir(parents=True, exist_ok=True)
    lock = load_json(project_dir / "package-lock.json", "lockfile")
    lock_rewritten = _rewrite_lockfile_for_target(lock, project_dir)
    manifest = load_json(project_dir / "package.json", "manifest")
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        if isinstance(manifest.get(key), dict):
            manifest[key] = _absolute_file_specs(manifest[key], project_dir)
    (target_dir / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (target_dir / "package-lock.json").write_text(
        json.dumps(lock_rewritten, indent=2) + "\n", encoding="utf-8")

    # 2. install with scripts DISABLED (defense-in-depth; npm 12 also blocks by default)
    code, out = run_capture(
        [npm_bin(), "ci", "--ignore-scripts", "--offline", "--no-fund", "--no-audit"],
        target_dir, logfile,
    )
    if code != 0:
        raise GateRefusal(f"final install failed (exit {code}): {out[-500:]}")


def invoke_approved_hooks(target_dir: Path, approved: list[dict],
                          logfile: Path | None) -> None:
    """Approved path, step 2 (AFTER post-unpack verification): invoke ONLY the approved
    benign package's own postinstall. The marker appears only after the approval record
    exists and the unpacked tree has been verified against the approved tarball."""
    for pkg in approved:
        name = pkg["name"]
        validate_package_name(name)
        pkg_root = target_dir / "node_modules" / name
        script = find_postinstall(pkg_root)
        if script is None:
            continue
        rcode, rtext = run_capture(["node", str(script)], pkg_root, logfile)
        if rcode != 0:
            raise GateRefusal(f"approved package postinstall failed (exit {rcode}): {rtext[-500:]}")


def resolve_phase(project_dir: Path, logfile: Path | None) -> None:
    """Resolve the tree with lifecycle scripts DISABLED (npm's own resolution)."""
    code, out = run_capture(
        [npm_bin(), "ci", "--dry-run", "--ignore-scripts", "--offline",
         "--no-fund", "--no-audit"],
        project_dir, logfile,
    )
    if code != 0:
        raise GateRefusal(
            f"npm resolution (scripts disabled) failed with exit {code}.\n{out[-800:]}")


def run_gate(project_dir: Path, allowlist_path: Path, logfile: Path | None,
             refuse_any_script=False) -> tuple[int, dict]:
    """Core gate. Returns (exit_code, report_dict). Never installs on non-ALLOW."""
    report: dict = {"steps": []}
    fail_closed_error = None

    try:
        # 0. manifest existence
        lock_path = project_dir / "package-lock.json"
        pkg_path = project_dir / "package.json"
        for p in (lock_path, pkg_path):
            if not p.is_file():
                raise GateRefusal(f"missing required file: {p.name} (pin a lockfile)")
        # 1. allowlist
        allowlist = load_json(allowlist_path, "allowlist")
        entries = allowlist.get("entries", {})
        if not isinstance(entries, dict) or not entries:
            raise GateRefusal("allowlist has no approved entries")

        # 2. lockfile FORMAT validation + parse BEFORE anything else touches the decision.
        #    An unrecognised format (e.g. v1), an empty 'packages' map, zero resolved
        #    artifacts, or a declared dependency with no resolved artifact is a FAULT and
        #    must REFUSE: never "no packages => nothing to check => allow".
        lock = load_json(lock_path, "lockfile")
        validate_lockfile(lock)
        resolved = parse_lockfile(lock, project_dir)
        if not resolved:
            raise GateRefusal(
                "zero resolved artifacts parsed from lockfile; refusing (fail-closed), "
                "an empty resolution is a fault, not 'nothing to check'")
        report["resolved_count"] = len(resolved)
        pkg_manifest = load_json(pkg_path, "package.json")
        if not isinstance(pkg_manifest, dict):
            raise GateRefusal("package.json root is not an object; refusing (fail-closed)")
        missing = missing_declared_dependencies(pkg_manifest, resolved)
        if missing:
            raise GateRefusal(
                "declared dependencies not resolved to any artifact: "
                f"{sorted(missing)}; refusing (fail-closed), the resolved set is incomplete")
        report["steps"].append("lockfile_format_validated")

        # 3. resolve with scripts disabled
        resolve_phase(project_dir, logfile)
        report["steps"].append("resolve_scripts_disabled")

        # 4. classify every resolved dependency scheme (fail-closed on unsupported)
        refused: list[str] = []
        for r in resolved:
            scheme = classify_resolved(r["resolved"])
            if scheme in ("git:", "http:", "https:", "unknown", "empty", "refused"):
                refused.append(f"{r['name']}: unsupported resolved scheme {scheme!r} ({r['resolved']})")
            elif r["has_install_script"] and refuse_any_script:
                refused.append(f"{r['name']}: install scripts requested but script execution forbidden")
        if refused:
            raise GateRefusal("unsupported input(s) refused: " + "; ".join(refused))

        # 5. per-artifact identity (sha256 of tarball bytes)
        findings = []
        unapproved: list[dict] = []
        per_pkg = []
        for r in resolved:
            try:
                sha, tarball_path = artifact_sha_for(r["resolved"], project_dir)
            except GateRefusal as exc:
                raise GateRefusal(f"{r['name']}: {exc}")
            per_pkg.append({"name": r["name"], "version": r["version"],
                            "sha256": sha, "resolved": r["resolved"],
                            "has_install_script": r["has_install_script"]})
            entry = entries.get(r["name"])
            reasons = []
            if entry is None:
                reasons.append("not-in-allowlist")
            else:
                if str(entry.get("version")) != str(r["version"]):
                    reasons.append(f"version-mismatch({r['version']} != {entry.get('version')})")
                if entry.get("sha256") != sha:
                    reasons.append("bytes-mismatch")
            if reasons:
                unapproved.append(r)
                findings.append({
                    "artifact": f"{r['name']}@{r['version']}",
                    "sha256": sha,
                    "approval_issue": reasons,
                })
        report["artifacts"] = per_pkg
        report["unapproved"] = findings

        # 6. composite identity (lock + bytes + allowlist + policy)
        identity_material = {
            "lockfile_sha256": sha256_bytes(lock_path.read_bytes()),
            "artifacts": {a["name"]: a["sha256"] for a in sorted(per_pkg, key=lambda x: x["name"])},
            "allowlist_sha256": sha256_bytes(allowlist_path.read_bytes()),
            "gate_policy_version": GATE_POLICY_VERSION,
        }
        composite = sha256_bytes(
            json.dumps(identity_material, sort_keys=True).encode("utf-8"))

        # 7. decide via the decision contract
        policy = build_gate_policy()
        evidence = build_evidence("", composite, unapproved, findings)
        verdict = dc.decide(evidence, policy)
        vd = verdict.to_dict()
        report["composite_identity_sha256"] = composite
        report["decision"] = vd
        report["action"] = vd["action"]
        report["verdict"] = vd["verdict"]

        if vd["action"] in ("allow", "monitor"):
            report["steps"].append("decision_allowed")
            return OK_EXIT, report
        report["steps"].append("decision_blocked")
        return BLOCK_EXIT, report

    except GateRefusal as exc:
        fail_closed_error = str(exc)
    except Exception as exc:  # noqa: BLE001 - fail-closed on ANY unexpected error
        fail_closed_error = f"unexpected error (fail-closed): {exc!r}"

    report["fail_closed_error"] = fail_closed_error
    report["action"] = "block"
    report["verdict"] = "hold"
    report["steps"].append("fail_closed")
    return ERROR_EXIT, report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="npm pre-install gate (fixtures only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_resolve = sub.add_parser("resolve", help="resolve tree with scripts disabled and report decision")
    p_resolve.add_argument("--project", required=True)
    p_resolve.add_argument("--allowlist", required=True)
    p_resolve.add_argument("--log")

    p_install = sub.add_parser("install", help="decide then (if ALLOW) final-install in --target")
    p_install.add_argument("--project", required=True)
    p_install.add_argument("--allowlist", required=True)
    p_install.add_argument("--target", required=True)
    p_install.add_argument("--no-final-install", action="store_true",
                           help="decide only; do NOT run the final install or the marker")
    p_install.add_argument("--log")

    args = ap.parse_args(argv)
    project_dir = Path(args.project).resolve()
    allowlist_path = Path(args.allowlist).resolve()
    logfile = Path(args.log).resolve() if args.log else None

    code, report = run_gate(project_dir, allowlist_path, logfile,
                            refuse_any_script=False)
    # stdout is PURE JSON (machine-parseable); status line goes to stderr
    print(json.dumps(report, indent=2, default=str))
    print(f"[gate] exit={code} action={report.get('action')} verdict={report.get('verdict')}",
          file=sys.stderr)

    if args.cmd == "install" and code == OK_EXIT and not args.no_final_install:
        target_dir = Path(args.target).resolve()
        composite = report.get("composite_identity_sha256", "")
        approved = report.get("artifacts", [])
        try:
            # 1. WRITE the tamper-evident identity-bound approval record FIRST: the marker
            #    may only appear AFTER this record exists (ordering guarantee).
            write_approval_record(target_dir, composite, report.get("decision", {}))
            # 2. VERIFY the record on read (self-hash + identity) BEFORE installing anything.
            verify_approval_record(target_dir, composite)
            # 3. approved final install into --target with scripts DISABLED.
            run_final_install(project_dir, target_dir, logfile)
            # 4. POST-UNPACK verification: installed tree vs the approved tarball, BEFORE
            #    any package hook is invoked. (Narrows, does not close, the TOCTOU residual.)
            results = verify_post_install(target_dir, approved, project_dir)
            write_verification_record(target_dir, results)
            # 5. now invoke ONLY the approved benign package's own postinstall.
            invoke_approved_hooks(target_dir, approved, logfile)
            print(f"[gate] FINAL INSTALL completed in {target_dir} (approved; approval record "
                  f"verified on read; post-unpack verification passed: "
                  f"{sum(r['files_verified'] for r in results)} file(s) across "
                  f"{len(results)} package(s)).", file=sys.stderr)
        except GateRefusal as exc:
            print(f"[gate] final-install/verification error (fail-closed): {exc}",
                  file=sys.stderr)
            return ERROR_EXIT
    return code


if __name__ == "__main__":
    raise SystemExit(main())
