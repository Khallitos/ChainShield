"""Scan context: what a scan compares packages against.

ChainShield is run by an organisation on its own repositories, so the trust baseline is the
*scanned project's* lockfile and the internal namespace policy is the *organisation's*
declaration. Similarity is measured against a standard, published popular-package list
(GuardDog top-8,000 npm packages). The demo-site baseline is used only in ``lab`` mode.

Modes
  * ``project`` (default for API scans): trusted = project lockfile; canonical names =
    lockfile names + popular reference; internal patterns = caller-declared.
  * ``lab``: the frozen demo-site baseline (``data/trusted/baseline.json``) used by the
    laboratory scenarios ATK1 to ATK3.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from app.policy.trusted_baseline import (
    TrustedBaseline,
    _build,
    get_trusted_baseline,
    normalize_name,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
POPULAR_REFERENCE_PATH = _PROJECT_ROOT / "data" / "reference" / "guarddog_top_npm_packages.json"
PUBLIC_NPM_REGISTRY = "registry.npmjs.org"

MODE_PROJECT = "project"
MODE_LAB = "lab"


@lru_cache(maxsize=1)
def popular_reference() -> Tuple[str, ...]:
    payload = json.loads(POPULAR_REFERENCE_PATH.read_text(encoding="utf-8"))
    names = payload["packages"] if isinstance(payload, dict) else payload
    return tuple(str(n) for n in names if isinstance(n, str) and n.strip())


def lockfile_packages(lockfile: Optional[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """``{name: {version, resolved, integrity}}`` from an npm lockfile (v1, v2 or v3) dict."""
    if not lockfile:
        return {}
    out: Dict[str, Dict[str, Any]] = {}
    packages = lockfile.get("packages")
    if isinstance(packages, Mapping):
        for key, meta in packages.items():
            if not key or not isinstance(meta, Mapping):
                continue  # "" is the root project
            name = meta.get("name") or key.split("node_modules/")[-1]
            out.setdefault(name, {
                "version": str(meta.get("version", "")),
                "resolved": meta.get("resolved"),
                "integrity": meta.get("integrity"),
                "source": "lockfile",
            })
    deps = lockfile.get("dependencies")
    if isinstance(deps, Mapping):  # lockfile v1
        stack: List[Mapping[str, Any]] = [deps]
        while stack:
            level = stack.pop()
            for name, meta in level.items():
                if not isinstance(meta, Mapping):
                    continue
                out.setdefault(name, {
                    "version": str(meta.get("version", "")),
                    "resolved": meta.get("resolved"),
                    "integrity": meta.get("integrity"),
                    "source": "lockfile",
                })
                nested = meta.get("dependencies")
                if isinstance(nested, Mapping):
                    stack.append(nested)
    return out


@dataclass(frozen=True)
class ScanContext:
    mode: str
    baseline: TrustedBaseline
    internal_patterns: Tuple[str, ...] = ()
    lockfile: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @property
    def graph(self) -> Dict[str, Any]:
        """Baseline in the dict shape used by the trust graph and feature extractor."""
        return {
            "baseline_id": self.baseline.baseline_id,
            "trusted_packages": dict(self.baseline.trusted_packages),
            "canonical_names": list(self.baseline.canonical_names),
            "internal_namespace_patterns": list(self.internal_patterns),
            "context_mode": self.mode,
        }

    def is_internal_name(self, name: str) -> bool:
        n = normalize_name(name)
        return any(re.match(p, n) for p in self.internal_patterns)

    def resolved_from_public_registry(self, name: str) -> Optional[bool]:
        """True/False when the project lockfile records where *name* resolved; None if unknown."""
        meta = self.lockfile.get(name)
        if not meta or not meta.get("resolved"):
            return None
        return PUBLIC_NPM_REGISTRY in str(meta["resolved"])


def _validated_patterns(patterns: Optional[Iterable[str]]) -> Tuple[str, ...]:
    out = []
    for p in patterns or ():
        p = str(p).strip()
        if not p:
            continue
        if not p.startswith("^"):
            # plain prefixes such as "@acme/" or "acme-internal-" are the common case
            p = "^" + re.escape(p)
        re.compile(p)
        out.append(p)
    return tuple(out)


def project_context(
    lockfile: Optional[Mapping[str, Any]] = None,
    internal_namespaces: Optional[Sequence[str]] = None,
) -> ScanContext:
    pkgs = lockfile_packages(lockfile)
    patterns = _validated_patterns(internal_namespaces)
    digest = hashlib.sha256(
        json.dumps({"lock": pkgs, "ns": patterns}, sort_keys=True, default=str).encode()
    ).hexdigest()[:12]
    payload = {
        "baseline_id": f"project:{digest}",
        "trusted_packages": pkgs,
        "canonical_names": list(pkgs) + list(popular_reference()),
        "internal_namespace_patterns": list(patterns),
    }
    baseline = _build(payload, Path(f"<project:{digest}>"))
    return ScanContext(MODE_PROJECT, baseline, patterns, pkgs)


@lru_cache(maxsize=1)
def lab_context() -> ScanContext:
    baseline = get_trusted_baseline()
    return ScanContext(MODE_LAB, baseline, tuple(baseline.internal_namespace_patterns), {})


def resolve_context(
    mode: Optional[str],
    lockfile: Optional[Mapping[str, Any]] = None,
    internal_namespaces: Optional[Sequence[str]] = None,
) -> ScanContext:
    if (mode or MODE_PROJECT) == MODE_LAB:
        return lab_context()
    return project_context(lockfile, internal_namespaces)


__all__ = [
    "MODE_LAB",
    "MODE_PROJECT",
    "POPULAR_REFERENCE_PATH",
    "ScanContext",
    "lab_context",
    "lockfile_packages",
    "popular_reference",
    "project_context",
    "resolve_context",
]
