"""
ATK1: Typosquatting attack module.

Provides:
  - levenshtein_distance()      edit-distance between two names
  - analyze_name_risk()         risk tier for a candidate vs ONE canonical name
  - analyze_against_baseline()  risk tier for a candidate vs the SUPPLIED trusted baseline
  - scan_manifest()             scan a dict of {name: version} pairs against the baseline
  - simulate_install()          resolve a name against the local DEMO registry (fixture only)
  - to_siem_event()             convert a result into a standard SIEM event dict

Names are compared against the supplied trusted baseline (``data/trusted/baseline.json`` via
``app.policy.trusted_baseline``). ``DEMO_REGISTRY`` is fixture data for ``simulate_install``'s
demo narrative only and never decides whether a name is risky.

An exact match to a baseline name is never reported as a typosquat. Lockfile depth is not used
as a legitimacy signal, because legitimate monorepo packages live in nested lockfiles. A
near-twin of an exact baseline match is reported only as a non-escalating advisory
(``BaselineNameRisk.advisory`` / ``ManifestScanResult.advisories``).

Limitation: a squatter that is itself part of the baseline is not caught by the near-twin
logic; it must be caught by a distance signal or by the explicit policy denylist below.

Explicit policy input: ``backend/app/policy/declared_squatters.json`` is a curated,
provenance-carrying DENYLIST of packages the lab DECLARES to be squatters. It is deliberately
separate from baseline membership (a name may be both) and its hits are labelled
``detection_basis='policy_denylist'`` so they are never mistaken for a similarity inference.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, Optional

from app.policy.trusted_baseline import (
    TrustedBaseline,
    get_trusted_baseline,
    normalize_name as _norm,
)

__all__ = [
    "levenshtein_distance",
    "analyze_name_risk",
    "TyposquatAnalysis",
    "BaselineNameRisk",
    "analyze_against_baseline",
    "scan_manifest",
    "ManifestScanResult",
    "simulate_install",
    "InstallSimulationResult",
    "to_siem_event",
    "DEMO_REGISTRY",
    "PackageRecord",
    "attacker_access_preview",
    "policy_denylist_entry",
    "policy_denylist_id",
]


# ── helpers ──────────────────────────────────────────────────────────────────

def levenshtein_distance(a: str, b: str) -> int:
    """Classic Levenshtein edit distance (insert / delete / substitute)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (0 if ca == cb else 1)))
        prev = cur
    return prev[-1]


# ── confusables (homoglyph handling) ─────────────────────────────────────────

# Bounded confusables map: non-ASCII characters that are visually identical to an ASCII
# letter. Keys are ALL non-ASCII, so an ASCII name can never be "homoglyphed", this is
# what keeps the `critical` tier reachable without over-flagging ordinary ASCII names.
_CONFUSABLES: Final[dict[str, str]] = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0441": "c", "\u0440": "p",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u043a": "k",
    "\u043c": "m", "\u043d": "h", "\u0442": "t", "\u0432": "b", "\u0455": "s",
    # Greek
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p", "\u03bd": "v",
    "\u03c4": "t", "\u03b9": "i", "\u03ba": "k", "\u03c5": "u", "\u03c3": "o",
    "\u03b7": "n", "\u03b2": "b", "\u03bb": "l", "\u03bc": "u",
    # Other common lookalikes
    "\u0131": "i", "\u0130": "i", "\u0451": "e", "\u04bb": "h",
    "\uff41": "a", "\uff45": "e", "\uff4f": "o",  # fullwidth latin
}

_LOW_MAX_DISTANCE: Final[int] = 3
# A scope add/remove only counts as a signal when the *name part* is the same or one edit
# away; otherwise unrelated scoped/unscoped packages would be cross-matched.
_SCOPE_MAX_DISTANCE: Final[int] = 1


def _confusable_skeleton(name: str) -> str:
    """Visual skeleton: NFKD, drop combining marks, fold known confusables to ASCII.

    Catches homoglyphs (Cyrillic 'а' for 'a'), accents added/removed, and fullwidth
    forms that plain NFKC + casefold does NOT fold together.
    """
    decomposed = unicodedata.normalize("NFKD", name)
    out: list[str] = []
    for ch in decomposed:
        if unicodedata.combining(ch):
            continue
        out.append(_CONFUSABLES.get(ch, ch))
    return "".join(out)


def _split_scope(norm_name: str) -> tuple[Optional[str], str]:
    """'@babel/core' -> ('@babel', 'core'); 'react' -> (None, 'react')."""
    if norm_name.startswith("@") and "/" in norm_name:
        scope, _, base = norm_name.partition("/")
        return scope, base
    return None, norm_name


def _effective_distance(rq_norm: str, cn_norm: str) -> tuple[int, int, bool, int]:
    """Effective comparison distance between two normalised names.

    Returns ``(effective, full, scope_changed, base)``. ``scope_changed`` is True only
    when EXACTLY one side is scoped (a scope added/removed); two different scopes are
    compared on the full name so unrelated scoped packages are not cross-matched. A scope
    change only lowers the effective distance when the name parts are within
    ``_SCOPE_MAX_DISTANCE``; otherwise the full-name distance is used.
    """
    full = levenshtein_distance(rq_norm, cn_norm)
    rq_scope, rq_base = _split_scope(rq_norm)
    cn_scope, cn_base = _split_scope(cn_norm)
    if (rq_scope is None) != (cn_scope is None):
        base_d = levenshtein_distance(rq_base, cn_base)
        if base_d <= _SCOPE_MAX_DISTANCE:
            return min(full, base_d), full, True, base_d
        return full, full, True, base_d
    return full, full, False, full


def _tier_from_distance(dist: int, max_len: int) -> tuple[str, float, str]:
    """Standard edit-distance risk ladder (no exact-match special case)."""
    similarity = 1.0 - dist / max(max_len, 1)
    if dist == 1:
        return "high", 0.90, "Single edit away, the classic typosquat distance."
    if dist == 2 and similarity >= 0.75:
        return "medium", 0.72, "Two edits, still visually similar."
    if dist <= _LOW_MAX_DISTANCE:
        return "low", 0.45, "Somewhat similar; context-dependent."
    return "none", 0.10, "Too dissimilar to be a typosquat of this canonical."


# ── name-risk analysis ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TyposquatAnalysis:
    requested: str
    canonical: str
    distance: int
    risk_tier: str          # none | low | medium | high | critical
    confidence: float       # 0.0-1.0
    note: str


def analyze_name_risk(requested: str, canonical: str) -> TyposquatAnalysis:
    """Compare *requested* against *canonical* and return a risk tier.

    Tiers (checked in this order, every branch is reachable):
      none      exact normalised match (or too dissimilar)
      critical  raw names differ but their confusable SKELETONS are identical
                (homoglyph / confusable substitution, accented lookalike)
      high      one edit away, OR a scope add/remove collision
      medium    two edits, similarity >= 0.75
      low       three edits or fewer

    The old ``critical`` branch ("dist == 0 but different letter-case") was unreachable
    because NFKC + casefold runs first and returns 'none' on equality. It is replaced by
    a genuine, reachable confusable check with the correct ordering.
    """
    rq, cn = _norm(requested), _norm(canonical)
    if not rq or not cn:
        return TyposquatAnalysis(requested, canonical, 999, "none", 0.0, "Empty name.")

    if rq == cn:
        return TyposquatAnalysis(
            requested, canonical, 0, "none", 1.0,
            "Exact normalised match, not a typosquat.",
        )

    # Reachable homoglyph / confusable tier: same visual skeleton, different codepoints.
    if _confusable_skeleton(rq) == _confusable_skeleton(cn):
        return TyposquatAnalysis(
            requested, canonical, levenshtein_distance(rq, cn), "critical", 0.93,
            "Homoglyph or confusable substitution that looks identical to the canonical name.",
        )

    eff, _full, scope_changed, base_d = _effective_distance(rq, cn)
    if scope_changed and base_d <= _SCOPE_MAX_DISTANCE:
        if base_d == 0:
            return TyposquatAnalysis(
                requested, canonical, 0, "high", 0.75,
                "Scope change: scoped/unscoped name collision with a trusted package name.",
            )
        return TyposquatAnalysis(
            requested, canonical, base_d, "high", 0.80,
            "Scope change plus a single edit in the name part.",
        )

    tier, conf, note = _tier_from_distance(eff, max(len(rq), len(cn)))
    return TyposquatAnalysis(requested, canonical, eff, tier, conf, note)


# ── candidate retrieval for large references ─────────────────────────────────

_INDEX_THRESHOLD: Final[int] = 400
_INDEX_CACHE: dict[tuple[str, int], tuple[tuple[str, ...], list[str], list[str]]] = {}


def _reference_index(bl: TrustedBaseline) -> tuple[tuple[str, ...], list[str], list[str]]:
    key = (bl.baseline_id, len(bl.canonical_names))
    cached = _INDEX_CACHE.get(key)
    if cached is None:
        names = bl.canonical_names
        norms = [_norm(n) for n in names]
        bases = [_split_scope(n)[1] for n in norms]
        cached = (names, norms, bases)
        if len(_INDEX_CACHE) > 16:
            _INDEX_CACHE.clear()
        _INDEX_CACHE[key] = cached
    return cached


def _candidate_canonicals(bl: TrustedBaseline, rq_norm: str) -> tuple[str, ...]:
    """Canonical names that can reach a flagged tier for *rq_norm*.

    Small (project) baselines are scanned exhaustively. For a large reference such as the
    8,000-name popular list, only names within the flagging distance of the full name, or
    within the scope-change distance of the name part, can change the result, so those are
    retrieved with a C Levenshtein implementation and then analysed exactly as before.
    """
    if len(bl.canonical_names) <= _INDEX_THRESHOLD:
        return bl.canonical_names
    try:
        from rapidfuzz.distance import Levenshtein
        from rapidfuzz.process import extract
    except ImportError:  # pragma: no cover - dependency listed in requirements
        return bl.canonical_names
    names, norms, bases = _reference_index(bl)
    hits = {i for _, _, i in extract(rq_norm, norms, scorer=Levenshtein.distance,
                                     score_cutoff=_LOW_MAX_DISTANCE, limit=None)}
    rq_base = _split_scope(rq_norm)[1]
    hits |= {i for _, _, i in extract(rq_base, bases, scorer=Levenshtein.distance,
                                      score_cutoff=_SCOPE_MAX_DISTANCE, limit=None)}
    skeleton = _confusable_skeleton(rq_norm)
    if skeleton != rq_norm:
        hits |= {i for _, _, i in extract(skeleton, norms, scorer=Levenshtein.distance,
                                          score_cutoff=_LOW_MAX_DISTANCE, limit=None)}
    return tuple(names[i] for i in sorted(hits))


# ── baseline-wide analysis ─────────────────────────────────

@dataclass(frozen=True)
class BaselineNameRisk:
    requested: str
    matched_canonical: Optional[str]
    distance: int
    risk_tier: str
    confidence: float
    note: str
    in_baseline: bool
    # Non-escalating side note. Set ONLY to make an ambiguous near-duplicate pair visible to a human;
    # it is not a finding, it never moves ``risk_tier``, and it must never be used as an accusation.
    advisory: Optional[str] = None

    @property
    def is_flagged(self) -> bool:
        return self.risk_tier in ("low", "medium", "high", "critical")


_UNKNOWN_NOTE: Final[str] = (
    "No similar canonical in the supplied trusted baseline; an unknown name is not "
    "treated as malicious."
)


def analyze_against_baseline(
    requested: str,
    baseline: Optional[TrustedBaseline] = None,
) -> BaselineNameRisk:
    """Compare *requested* against the SUPPLIED baseline (not the demo registry).

    Semantics for a name absent from the baseline: ``risk_tier='none'``,
    ``in_baseline=False``, ``matched_canonical=None``, explicitly *not* malicious.

    An exact baseline match is ALWAYS ``none``: an exact match to a supplied-baseline canonical is
    never accused as a typosquat. When the supplied baseline also lists a *different* canonical
    within one edit, that ambiguous near-duplicate is surfaced ONLY as a non-escalating
    ``advisory`` so a human can see it, it does not change the tier, does not produce a finding and
    is never used to accuse either member.
    """
    bl = baseline or get_trusted_baseline()
    rq = _norm(requested)
    if not rq:
        return BaselineNameRisk(requested, None, 999, "none", 0.0, "Empty name.", False)

    exact = bl.canonical_for(requested)

    best_key: Optional[tuple[int, int]] = None
    best_canon: Optional[str] = None
    best_full = 999
    for candidate in _candidate_canonicals(bl, rq):
        cn = _norm(candidate)
        if cn == rq:
            continue
        eff, full, _scope_changed, _base = _effective_distance(rq, cn)
        key = (eff, full)
        if best_key is None or key < best_key:
            best_key, best_canon, best_full = key, candidate, full

    if exact is not None:
        advisory: Optional[str] = None
        if best_key is not None and best_key[0] <= 1 and best_canon is not None:
            # A near-duplicate pair exists *inside* the supplied baseline. We do NOT try to decide
            # which member is the squatter: lockfile depth is not a legitimacy proxy (legitimate
            # monorepo / sub-project packages live in nested lockfiles), so provenance cannot pick
            # the guilty party here. Surface the ambiguity as advice only; the exact match stays
            # trusted. Resolution belongs to a human or to the explicit policy denylist.
            advisory = (
                f"ADVISORY ONLY (not a finding, not an accusation): '{requested}' exactly matches "
                f"the supplied baseline, but the baseline also lists near-duplicate '{best_canon}' "
                f"(edit distance {best_key[0]}). The pair is ambiguous and needs human review or an "
                "explicit policy denylist to resolve; lockfile depth is not treated as evidence."
            )
        return BaselineNameRisk(
            requested, exact, 0, "none", 1.0,
            "Exact match against the supplied trusted baseline, not a typosquat.", True,
            advisory,
        )

    if best_key is None or best_key[0] > _LOW_MAX_DISTANCE:
        return BaselineNameRisk(
            requested, None, best_full, "none", 0.10, _UNKNOWN_NOTE, False,
        )

    a = analyze_name_risk(requested, best_canon)
    return BaselineNameRisk(
        requested, best_canon, a.distance, a.risk_tier, a.confidence, a.note, False,
    )


# ── demo registry (local lab only, no public npm/PyPI) ────────────────────────

@dataclass(frozen=True)
class PackageRecord:
    display_name: str
    trusted: bool
    publisher: str
    summary: str
    simulated_effect: str
    # For malicious lab packages only: what install-time code can do (teaching aid).
    attacker_capabilities: tuple[str, ...] = ()
    masquerades_as: Optional[str] = None  # intended legitimate package name


def attacker_access_preview(rec: PackageRecord) -> dict[str, Any]:
    """Structured list of what a real postinstall typosquat could observe (lab narrative)."""
    return {
        "malicious_package": rec.display_name,
        "masquerades_as": rec.masquerades_as,
        "capabilities": list(rec.attacker_capabilities),
        "typical_exfil_surface": [
            "Process environment (CI tokens, registry auth, cloud keys, internal URLs)",
            "Host identity (hostname, OS, username)",
            "Repository context (cwd, branch hints from env, package manager metadata)",
            "Network egress to attacker-controlled HTTPS endpoint (or DNS exfiltration)",
        ],
        "lab_artifact": "After a real `npm install`, see demo-site/attack-exfil-report.json",
    }


DEMO_REGISTRY: Final[dict[str, PackageRecord]] = {
    # ── ATK1 demo pair (matches demo-site/packages/) ──────────────────────────
    "training-ledger": PackageRecord(
        display_name="training-ledger",
        trusted=True,
        publisher="internal-lab",
        summary="Intended finance-training helper (correct spelling).",
        simulated_effect="No-op: trusted package runs normal library code.",
    ),
    "training-leder": PackageRecord(
        display_name="training-leder",
        trusted=False,
        publisher="unknown-squatter",
        summary="Typosquat of training-ledger (missing 'g').",
        simulated_effect=(
            "[DEMO ONLY] Postinstall hook would read env vars "
            "(DEMO_SECRET, CI tokens) and POST to attacker collector."
        ),
        masquerades_as="training-ledger",
        attacker_capabilities=(
            "postinstall script runs automatically on npm/yarn install",
            "read process environment (tokens, secrets, internal endpoints)",
            "read cwd / repo path; infer project and CI context",
            "open outbound HTTPS to exfiltrate captured data (lab: writes attack-exfil-report.json)",
            "run arbitrary Node code as the developer or CI user",
        ),
    ),
    # ── secondary demo pair ──────────────────────────────────────────────────
    "acme-ledger": PackageRecord(
        display_name="acme-ledger",
        trusted=True,
        publisher="acme-oss",
        summary="Legitimate demo helper (acme example).",
        simulated_effect="No-op.",
    ),
    "acme-leder": PackageRecord(
        display_name="acme-leder",
        trusted=False,
        publisher="unknown-maintainer-4821",
        summary="Typosquat of acme-ledger.",
        simulated_effect=(
            "[DEMO ONLY] Postinstall script would exfiltrate env vars."
        ),
        masquerades_as="acme-ledger",
        attacker_capabilities=(
            "postinstall script runs automatically on npm/yarn install",
            "read process environment and host metadata",
            "exfiltrate over network or write local staging files",
        ),
    ),
}


# ── install simulation ────────────────────────────────────────────────────────

@dataclass
class InstallSimulationResult:
    requested: str
    resolved_key: Optional[str]
    outcome: str            # trusted_install | typosquat_install | not_found
    record: Optional[PackageRecord]
    attacker_success: bool
    presentation_lines: list[str] = field(default_factory=list)
    attacker_access_preview: Optional[dict[str, Any]] = None


def simulate_install(requested: str) -> InstallSimulationResult:
    """Resolve *requested* against the local demo registry (exact name, case-insensitive)."""
    key = _norm(requested)
    rec = DEMO_REGISTRY.get(key)
    lines: list[str] = [f"resolver: looking up '{requested}' …"]

    if rec is None:
        lines.append("resolver: not found in demo registry.")
        return InstallSimulationResult(
            requested=requested, resolved_key=None,
            outcome="not_found", record=None,
            attacker_success=False, presentation_lines=lines,
            attacker_access_preview=None,
        )

    lines += [
        f"resolver: found '{rec.display_name}'",
        f"resolver: publisher = {rec.publisher}",
        f"resolver: trusted   = {rec.trusted}",
    ]

    if rec.trusted:
        lines.append("post-install: benign, expected library behaviour.")
        return InstallSimulationResult(
            requested=requested, resolved_key=key,
            outcome="trusted_install", record=rec,
            attacker_success=False, presentation_lines=lines,
            attacker_access_preview=None,
        )

    preview = attacker_access_preview(rec)
    lines += [
        "post-install: *** TYPOSQUAT DETECTED: attacker code path triggered ***",
        rec.simulated_effect,
        "attacker: would gain the access surface described in attacker_access_preview (API + postinstall report).",
    ]
    return InstallSimulationResult(
        requested=requested, resolved_key=key,
        outcome="typosquat_install", record=rec,
        attacker_success=True, presentation_lines=lines,
        attacker_access_preview=preview,
    )


# ── explicit policy input: curated declared-squatter denylist ─────────────────
#
# Deliberately SEPARATE from trusted-baseline membership. A name listed here is reported as a
# squatter because a human/policy DECLARED it so, with recorded provenance, never because of a
# similarity inference or lockfile provenance. The data file lives in the revised tree
# (``backend/app/policy/declared_squatters.json``); the frozen ``data/trusted/baseline.json`` is
# untouched and a name may be a member of both.

_DENYLIST_PATH: Final = Path(__file__).resolve().parent.parent / "policy" / "declared_squatters.json"
_DENYLIST_CACHE: Optional[dict[str, Any]] = None


def _load_policy_denylist() -> dict[str, Any]:
    """Load (and cache) the curated declared-squatter policy input."""
    global _DENYLIST_CACHE
    if _DENYLIST_CACHE is None:
        try:
            with _DENYLIST_PATH.open("r", encoding="utf-8") as fh:  # read-only
                payload = json.load(fh)
        except FileNotFoundError:
            payload = {"policy_id": "none", "entries": {}}
        if not isinstance(payload, dict):
            payload = {"policy_id": "none", "entries": {}}
        _DENYLIST_CACHE = payload
    return _DENYLIST_CACHE


def policy_denylist_id() -> str:
    """Stable id of the active declared-squatter policy input."""
    return str(_load_policy_denylist().get("policy_id") or "declared-squatters")


def policy_denylist_entry(name: str) -> Optional[dict[str, Any]]:
    """Return the explicit declared-squatter entry for *name*, or None.

    This is a POLICY lookup, not a baseline lookup: matching here is an explicit declaration, not a
    similarity inference. Case-insensitive / NFKC-normalised to match the rest of the module.
    """
    entries = _load_policy_denylist().get("entries") or {}
    if not isinstance(entries, dict):
        return None
    key = _norm(name)
    for entry_name, entry in entries.items():
        if _norm(entry_name) == key and isinstance(entry, dict):
            return dict(entry)
    return None


def reset_policy_denylist_cache() -> None:
    """Drop the policy-input cache (tests / explicit reloads)."""
    global _DENYLIST_CACHE
    _DENYLIST_CACHE = None


# ── manifest scanner (reads package.json-style dict) ─────────────────────────

@dataclass
class ManifestScanResult:
    scanned: int
    findings: list[dict[str, Any]]
    risk_summary: dict[str, int]
    # Non-escalating notes (e.g. ambiguous baseline near-twins). Never findings, never scored.
    advisories: list[dict[str, Any]] = field(default_factory=list)


def _demo_ornament(pkg_name: str, canonical: str) -> tuple[bool, Optional[dict[str, Any]], str]:
    """Demo-lab narrative for a *flag-needing* name whose canonical is a DEMO_REGISTRY target.

    Display only: never a decision input.
    """
    demo = DEMO_REGISTRY.get(_norm(pkg_name))
    if (
        demo is not None
        and not demo.trusted
        and demo.masquerades_as
        and _norm(demo.masquerades_as) == _norm(canonical)
    ):
        return True, attacker_access_preview(demo), demo.simulated_effect
    return False, None, "n/a"


def scan_manifest(
    dependencies: dict[str, str],
    baseline: Optional[TrustedBaseline] = None,
    use_policy_denylist: bool = True,
) -> ManifestScanResult:
    """Scan a *dependencies* dict ``{name: version}`` against the SUPPLIED trusted baseline.

    Two independent signal sources:
      1. Explicit policy denylist (``declared_squatters.json``), a curated DECLARATION. Hits carry
         ``detection_basis='policy_denylist'`` and their declared tier.
      2. The supplied baseline: distance-based similarity only. An exact baseline match is never a
         finding; an ambiguous near-twin is emitted as a non-escalating ADVISORY instead.
    The demo registry is NOT consulted for the risk decision; it only decorates a flagged finding
    whose canonical is its documented ``masquerades_as`` target. A name simply absent from the
    baseline is neither flagged nor labelled malicious (see ``analyze_against_baseline``).
    """
    bl = baseline or get_trusted_baseline()
    findings: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    risk_summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}

    for pkg_name in dependencies:
        # The declared-squatter list is a laboratory policy input; project scans do not use it.
        entry = policy_denylist_entry(pkg_name) if use_policy_denylist else None
        if entry is not None:
            canonical = str(entry.get("canonical") or "")
            tier = str(entry.get("tier") or "high")
            demo_narrative, preview, simulated = _demo_ornament(pkg_name, canonical)
            findings.append({
                "package": pkg_name,
                "canonical": canonical,
                "distance": levenshtein_distance(_norm(pkg_name), _norm(canonical)),
                "risk_tier": tier,
                "confidence": float(entry.get("confidence", 0.95)),
                "note": (
                    f"Policy denylist hit: '{pkg_name}' is a known"
                    f" {entry.get('squat_type', 'squat')} of '{canonical}'."
                ),
                "policy_source": policy_denylist_id(),
                "policy_provenance": entry.get("provenance"),
                "attacker_success": demo_narrative,
                "simulated_effect": simulated,
                "attacker_access_preview": preview,
                "detection_basis": "policy_denylist",
            })
            risk_summary[tier] = risk_summary.get(tier, 0) + 1
            continue

        assessment = analyze_against_baseline(pkg_name, bl)
        if assessment.advisory:
            advisories.append({"package": pkg_name, "advisory": assessment.advisory})
        if not assessment.is_flagged or not assessment.matched_canonical:
            continue

        canonical = assessment.matched_canonical
        demo_narrative, preview, simulated = _demo_ornament(pkg_name, canonical)
        findings.append({
            "package": pkg_name,
            "canonical": canonical,
            "distance": assessment.distance,
            "risk_tier": assessment.risk_tier,
            "confidence": assessment.confidence,
            "note": assessment.note,
            "attacker_success": demo_narrative,
            "simulated_effect": simulated,
            "attacker_access_preview": preview,
            "detection_basis": "baseline_similarity",
        })
        risk_summary[assessment.risk_tier] = risk_summary.get(assessment.risk_tier, 0) + 1

    return ManifestScanResult(
        scanned=len(dependencies),
        findings=findings,
        risk_summary=risk_summary,
        advisories=advisories,
    )


# ── SIEM event builder ────────────────────────────────────────────────────────

def to_siem_event(finding: dict[str, Any], source: str = "demo-site") -> dict[str, Any]:
    """Convert a manifest finding into the standard SIEM event schema."""
    ev: dict[str, Any] = {
        "event_id": f"ATK1-{finding['package']}-{finding['canonical']}",
        "attack_type": "typosquatting",
        "severity": finding["risk_tier"],
        "confidence": finding["confidence"],
        "source": source,
        "package": finding["package"],
        "canonical": finding["canonical"],
        "distance": finding["distance"],
        "attacker_success": finding["attacker_success"],
        "simulated_effect": finding["simulated_effect"],
        "note": finding["note"],
        "recommendation": (
            f"Replace '{finding['package']}' with the intended "
            f"'{finding['canonical']}' and pin the exact version."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if finding.get("attacker_access_preview"):
        ev["attacker_access_preview"] = finding["attacker_access_preview"]
    # Distinguish an explicit policy declaration from a similarity inference for SIEM consumers.
    if finding.get("detection_basis"):
        ev["detection_basis"] = finding["detection_basis"]
    return ev
