"""Trust graph drift detection against data-derived baseline."""
from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from app.attacks.typosquatting import analyze_name_risk, levenshtein_distance
from app.services.baseline_builder import load_baseline, matches_internal_namespace


PUBLIC_HIGH_MAJOR = 90


@lru_cache(maxsize=8)
def _lowered(names: Tuple[str, ...]) -> Tuple[str, ...]:
    return tuple(n.lower() for n in names)


def _nearest_canonical(name: str, canonical_names: List[str]) -> Tuple[int, Optional[str]]:
    """Minimum edit distance to any canonical name (case-insensitive) and that name."""
    if not canonical_names:
        return 999, None
    if len(canonical_names) > 400:
        try:
            from rapidfuzz.distance import Levenshtein
            from rapidfuzz.process import extractOne

            hit = extractOne(name.lower(), _lowered(tuple(canonical_names)),
                             scorer=Levenshtein.distance)
            if hit is not None:
                return int(hit[1]), canonical_names[hit[2]]
        except ImportError:  # pragma: no cover - dependency listed in requirements
            pass
    best, nearest = 999, None
    for canonical in canonical_names:
        d = levenshtein_distance(name.lower(), canonical.lower())
        if d < best:
            best, nearest = d, canonical
    return best, nearest


def get_trusted_graph(baseline_id: str = "default") -> Dict[str, Any]:
    baseline = load_baseline()
    if baseline.get("baseline_id") != baseline_id and baseline_id != "default":
        # Lab: single profile for now
        pass
    return baseline


def _version_parts(version: str) -> Tuple[int, ...]:
    nums: List[int] = []
    for part in str(version).split("."):
        try:
            nums.append(int("".join(c for c in part if c.isdigit()) or "0"))
        except ValueError:
            nums.append(0)
    return tuple(nums) if nums else (0,)


def version_gap_score(requested: str, trusted: str) -> float:
    """Higher when requested semver is much larger than trusted (dep confusion signal)."""
    rq, tr = _version_parts(requested), _version_parts(trusted)
    if rq <= tr:
        return 0.0
    major_gap = (rq[0] - tr[0]) if rq and tr else 0
    if major_gap >= 8:
        return 0.95
    if major_gap >= 1:
        return 0.55 + min(major_gap * 0.05, 0.35)
    return 0.25


def check_package_drift(
    name: str,
    version: str,
    baseline: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Compare one dependency against the trust graph.
    Returns drift flags used by feature extractor and hybrid scorer.
    """
    baseline = baseline or get_trusted_graph()
    trusted_pkgs = baseline.get("trusted_packages") or {}
    canonical_names = baseline.get("canonical_names") or []
    patterns = baseline.get("internal_namespace_patterns") or []

    exact = name in trusted_pkgs
    trusted_meta = trusted_pkgs.get(name, {})
    trusted_version = str(trusted_meta.get("version", "0.0.0"))

    # In project mode trust attaches to the ARTIFACT the lockfile records (name and version), not
    # to the name: a new release of a trusted package is scored on its own content.
    if baseline.get("context_mode") == "project":
        trusted_artifact = exact and str(version).lstrip("^~=v ") == trusted_version
    else:
        trusted_artifact = exact

    min_edit, nearest_canonical = _nearest_canonical(name, canonical_names)

    typo = (
        analyze_name_risk(name, nearest_canonical)
        if nearest_canonical and not exact
        else None
    )

    is_internal_style = matches_internal_namespace(name, patterns)
    # A version gap can only be computed against a KNOWN trusted version. For an exact trusted
    # match that is the version the baseline recorded for the package (its declared provenance).
    # For an internal-style name that is NOT an exact trusted match there is no known trusted
    # version, so the gap is genuinely unknowable and is reported as 0.0. The previous code
    # compared such names against a hardcoded constant "1.4.2", which implied knowledge the system
    # does not have. Detection of these names does not depend on the version signal: the
    # internal-namespace clause below still flags them.
    ver_gap = version_gap_score(version, trusted_version) if exact else 0.0

    major = _version_parts(version)[0]
    # Declared internal name at a high major version, or any package published at an
    # implausibly high major version (>= 90), the version-precedence trick used by public
    # dependency-confusion packages.
    public_high_version = (is_internal_style and major >= 9) or major >= PUBLIC_HIGH_MAJOR

    drift = (
        (not exact and min_edit == 1)
        or (
            not exact
            and min_edit <= 2
            and typo
            and typo.risk_tier in ("high", "medium", "critical")
        )
        or (exact and public_high_version)
        or (exact and ver_gap >= 0.85)
        or (is_internal_style and not exact and min_edit > 0)
    )

    return {
        "package": name,
        "version": version,
        "exact_trusted_match": trusted_artifact,
        "min_edit_distance": min_edit,
        "nearest_canonical": nearest_canonical,
        "typosquat_risk_tier": typo.risk_tier if typo else "none",
        "version_gap_score": round(ver_gap, 3),
        "internal_namespace": is_internal_style,
        "public_high_version": public_high_version,
        "baseline_drift": drift,
        "trusted_source": trusted_meta.get("source"),
    }
