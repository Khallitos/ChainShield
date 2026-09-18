"""Read-only loader for the SUPPLIED trusted package baseline.

Authority for typosquat / dependency-confusion name decisions. Loads
``data/trusted/baseline.json`` (frozen, hash-pinned) or any caller-supplied path.

Design notes:
  * Read-only: the file is opened for reading and never written. The module exposes no
    writer; rebuilding the baseline is ``app.services.baseline_builder``'s job.
  * Names are normalised with NFKC + strip + casefold for lookup, and BOTH scoped
    (``@scope/name``) and unscoped names are supported.
  * This module contains data access only, no edit-distance algorithm (that stays in
    ``app.attacks.typosquatting``) so there is no import cycle.
"""
from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple, Union

__all__ = [
    "DEFAULT_BASELINE_PATH",
    "TrustedBaseline",
    "load_trusted_baseline",
    "get_trusted_baseline",
    "reset_trusted_baseline_cache",
]

# backend/app/policy/trusted_baseline.py -> parents[3] = repository root
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BASELINE_PATH = _PROJECT_ROOT / "data" / "trusted" / "baseline.json"

PathLike = Union[str, Path]


def normalize_name(name: str) -> str:
    """NFKC + strip + casefold, the one normalisation used for every name lookup."""
    return unicodedata.normalize("NFKC", name or "").strip().casefold()


@dataclass(frozen=True)
class TrustedBaseline:
    """Immutable view over a supplied trusted baseline."""

    baseline_id: str
    source_path: str
    canonical_names: Tuple[str, ...]
    trusted_packages: Mapping[str, Mapping[str, Any]]
    internal_namespace_patterns: Tuple[str, ...]
    registry_policy: Mapping[str, Any]
    _by_norm: Mapping[str, str]

    # ── lookups ───────────────────────────────────────────────────────────────
    def canonical_for(self, name: str) -> Optional[str]:
        """Return the stored canonical form for an exact (normalised) match, else None."""
        return self._by_norm.get(normalize_name(name))

    def is_canonical(self, name: str) -> bool:
        """True when the (normalised) name is exactly a trusted baseline canonical."""
        return normalize_name(name) in self._by_norm

    def trusted_meta(self, name: str) -> Mapping[str, Any]:
        canon = self.canonical_for(name)
        return self.trusted_packages.get(canon, {}) if canon else {}

    def declared_lockfile(self, name: str) -> Optional[str]:
        """The lockfile the baseline recorded for *name* (provenance), if any."""
        meta = self.trusted_meta(name)
        value = meta.get("from_lockfile")
        return str(value) if value else None

    def is_internal_name(self, name: str) -> bool:
        """Match against the baseline's declared internal-namespace patterns."""
        import re

        n = normalize_name(name)
        return any(re.match(p, n) for p in self.internal_namespace_patterns)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "source_path": self.source_path,
            "canonical_count": len(self.canonical_names),
            "internal_namespace_patterns": list(self.internal_namespace_patterns),
            "registry_policy": dict(self.registry_policy),
        }


def _read_payload(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:  # read-only, never written
        return json.load(fh)


def _build(payload: Mapping[str, Any], source_path: Path) -> TrustedBaseline:
    trusted_packages: Dict[str, Mapping[str, Any]] = dict(payload.get("trusted_packages") or {})
    declared = list(payload.get("canonical_names") or [])
    # canonical_names is authoritative when present; trusted_packages keys are unioned in
    # so a baseline supplied without the derived list still works.
    ordered: list[str] = []
    seen: set[str] = set()
    for name in declared + list(trusted_packages.keys()):
        if not isinstance(name, str) or not name.strip():
            continue
        key = normalize_name(name)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(name)

    by_norm = {normalize_name(n): n for n in ordered}
    return TrustedBaseline(
        baseline_id=str(payload.get("baseline_id") or "unknown"),
        source_path=str(source_path),
        canonical_names=tuple(ordered),
        trusted_packages=trusted_packages,
        internal_namespace_patterns=tuple(payload.get("internal_namespace_patterns") or ()),
        registry_policy=dict(payload.get("registry_policy") or {}),
        _by_norm=by_norm,
    )


_CACHE: Dict[str, TrustedBaseline] = {}


def load_trusted_baseline(path: Optional[PathLike] = None) -> TrustedBaseline:
    """Load a trusted baseline from *path* (default: ``data/trusted/baseline.json``).

    Raises FileNotFoundError when the supplied path is missing. The default path is
    frozen repository data; callers never write here.
    """
    target = Path(path) if path is not None else DEFAULT_BASELINE_PATH
    resolved = str(target)
    cached = _CACHE.get(resolved)
    if cached is not None:
        return cached
    if not target.is_file():
        raise FileNotFoundError(f"Trusted baseline not found: {target}")
    baseline = _build(_read_payload(target), target)
    _CACHE[resolved] = baseline
    return baseline


def get_trusted_baseline() -> TrustedBaseline:
    """Cached accessor for the repository's default trusted baseline."""
    return load_trusted_baseline(DEFAULT_BASELINE_PATH)


def reset_trusted_baseline_cache() -> None:
    """Drop the load cache (tests / explicit reloads)."""
    _CACHE.clear()
