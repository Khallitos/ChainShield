"""
ATK2: Dependency confusion attack simulation (safe, local, no real registry access).

The model here simulates two registries:
  - internal (trusted corporate source)
  - public (untrusted internet source)

If resolver precedence is misconfigured, a same-name public package can win.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final, Optional


@dataclass(frozen=True)
class RegistryPackage:
    name: str
    version: str
    source: str  # internal | public
    trusted: bool
    publisher: str
    simulated_effect: str


INTERNAL_REGISTRY: Final[dict[str, RegistryPackage]] = {
    "corp-internal-ledger-api": RegistryPackage(
        name="corp-internal-ledger-api",
        version="1.4.2",
        source="internal",
        trusted=True,
        publisher="corp-security-platform",
        simulated_effect="Normal internal ledger synchronization helper.",
    ),
    "corp-internal-ledger-sync": RegistryPackage(
        name="corp-internal-ledger-sync",
        version="2.0.1",
        source="internal",
        trusted=True,
        publisher="corp-finops",
        simulated_effect="Normal internal reconciliation batch helper.",
    ),
}

PUBLIC_REGISTRY: Final[dict[str, RegistryPackage]] = {
    # Same names as internal packages to simulate confusion attempts.
    "corp-internal-ledger-api": RegistryPackage(
        name="corp-internal-ledger-api",
        version="9.9.9",
        source="public",
        trusted=False,
        publisher="unknown-publisher",
        simulated_effect=(
            "[DEMO ONLY] Public lookalike package could execute install hooks and "
            "collect environment and repository metadata."
        ),
    ),
    "corp-internal-ledger-sync": RegistryPackage(
        name="corp-internal-ledger-sync",
        version="7.7.0",
        source="public",
        trusted=False,
        publisher="squatted-maintainer",
        simulated_effect=(
            "[DEMO ONLY] Public twin package could run malicious code path in CI."
        ),
    ),
}


@dataclass(frozen=True)
class ResolverPolicy:
    prefer_internal: bool = True
    allow_public_fallback_for_internal_names: bool = False
    enforce_internal_namespace_block: bool = True


@dataclass
class ResolutionResult:
    package_name: str
    requested_version: str
    outcome: str  # safe_internal | blocked_policy | confused_public | not_found
    resolved: Optional[RegistryPackage]
    attacker_success: bool
    reason: str


def is_internal_style_name(name: str) -> bool:
    return name.startswith("corp-internal-")


def simulate_resolution(
    package_name: str,
    requested_version: str,
    policy: Optional[ResolverPolicy] = None,
) -> ResolutionResult:
    policy = policy or ResolverPolicy()
    internal = INTERNAL_REGISTRY.get(package_name)
    public = PUBLIC_REGISTRY.get(package_name)
    internal_name = is_internal_style_name(package_name)

    if internal_name and policy.enforce_internal_namespace_block and internal is None and public is not None:
        return ResolutionResult(
            package_name=package_name,
            requested_version=requested_version,
            outcome="blocked_policy",
            resolved=None,
            attacker_success=False,
            reason="Internal namespace policy blocked unknown internal-style package from public registry.",
        )

    if policy.prefer_internal and internal is not None:
        return ResolutionResult(
            package_name=package_name,
            requested_version=requested_version,
            outcome="safe_internal",
            resolved=internal,
            attacker_success=False,
            reason="Resolver preferred internal registry package.",
        )

    if public is not None and (
        not internal_name or policy.allow_public_fallback_for_internal_names or internal is None
    ):
        return ResolutionResult(
            package_name=package_name,
            requested_version=requested_version,
            outcome="confused_public",
            resolved=public,
            attacker_success=True,
            reason="Public package resolved for internal-style dependency name.",
        )

    if internal is not None:
        return ResolutionResult(
            package_name=package_name,
            requested_version=requested_version,
            outcome="safe_internal",
            resolved=internal,
            attacker_success=False,
            reason="Internal package resolved.",
        )

    return ResolutionResult(
        package_name=package_name,
        requested_version=requested_version,
        outcome="not_found",
        resolved=None,
        attacker_success=False,
        reason="Package not found in simulated registries.",
    )


# ── evidence-based dependency-confusion assessment ── ────────────────────────
#
# A high/major version number is NOT proof of an attack. On its own it is only an
# advisory signal. A dependency-confusion finding requires explicit evidence:
#   * private_name_declared  , the name is declared private/internal
#   * allowed_registry_policy, an explicit allowed-registry / namespace policy is set
#   * resolution_evidence    , registry or resolution information for the name is available
# When any of these is unavailable the result is INSUFFICIENT_EVIDENCE, never a finding.
#
# NOTE (resolved): the earlier residual, `app/services/trust_graph.py` deriving a
# version-gap signal from a hardcoded trusted version literal "1.4.2" for internal-style
# names absent from the baseline: has been REMOVED. `trust_graph.check_package_drift` now
# computes a version gap only against a KNOWN trusted version (which, for an exact trusted
# match, is the version the baseline recorded for the package) and reports 0.0 otherwise;
# internal-style names that are not exact matches are still flagged by the internal-namespace
# clause, so detection does not depend on the version signal. This module likewise uses no
# hardcoded trusted version at all.

INSUFFICIENT_EVIDENCE: Final[str] = "insufficient_evidence"


@dataclass(frozen=True)
class ConfusionEvidence:
    """Explicit evidence required before a confusion finding may be raised."""

    private_name_declared: bool = False
    allowed_registry_policy: bool = False
    resolution_evidence: bool = False

    @property
    def complete(self) -> bool:
        return (
            self.private_name_declared
            and self.allowed_registry_policy
            and self.resolution_evidence
        )

    def missing(self) -> list[str]:
        return [
            name
            for name, present in (
                ("private_name_declared", self.private_name_declared),
                ("allowed_registry_policy", self.allowed_registry_policy),
                ("resolution_evidence", self.resolution_evidence),
            )
            if not present
        ]


def _major_version(version: str) -> int:
    head = str(version or "").lstrip("^~><=v ").split(".")[0]
    digits = "".join(c for c in head if c.isdigit())
    return int(digits) if digits else 0


def assess_dependency_confusion(
    package_name: str,
    requested_version: str = "*",
    *,
    evidence: Optional[ConfusionEvidence] = None,
    policy: Optional[ResolverPolicy] = None,
) -> dict[str, Any]:
    """Evidence-based dependency-confusion assessment.

    Outcomes:
      not_applicable        name is not declared private/internal
      insufficient_evidence required evidence is missing (a high version alone lands here)
      safe_internal         resolved to the trusted internal source
      confirmed_confusion   resolved to public for a private name
      blocked_by_policy     internal-namespace policy blocked the public source
    """
    ev = evidence or ConfusionEvidence()
    pol = policy or ResolverPolicy()
    name = (package_name or "").strip()
    high_version = _major_version(requested_version) >= 8  # advisory signal only

    base: dict[str, Any] = {
        "package": name,
        "requested_version": requested_version,
        "version_signal": high_version,
        "evidence": {
            "private_name_declared": ev.private_name_declared,
            "allowed_registry_policy": ev.allowed_registry_policy,
            "resolution_evidence": ev.resolution_evidence,
        },
    }

    if not (ev.private_name_declared or is_internal_style_name(name)):
        return {
            **base,
            "outcome": "not_applicable",
            "severity": "none",
            "attacker_success": False,
            "reason": "Name is not declared private/internal; dependency confusion is not applicable.",
        }

    if not ev.complete:
        return {
            **base,
            "outcome": INSUFFICIENT_EVIDENCE,
            "severity": "none",
            "attacker_success": False,
            "reason": (
                "Insufficient evidence: missing "
                + ", ".join(ev.missing())
                + ". A high version number alone is not proof of dependency confusion."
            ),
        }

    res = simulate_resolution(name, requested_version, pol)
    outcome_map = {
        "confused_public": "confirmed_confusion",
        "safe_internal": "safe_internal",
        "blocked_policy": "blocked_by_policy",
        "not_found": "unresolved",
    }
    outcome = outcome_map.get(res.outcome, "unresolved")
    severity = "high" if outcome == "confirmed_confusion" else "none"
    return {
        **base,
        "outcome": outcome,
        "severity": severity,
        "attacker_success": res.attacker_success,
        "reason": res.reason,
        "resolved_source": res.resolved.source if res.resolved else None,
        "resolved_version": res.resolved.version if res.resolved else None,
    }


def scan_manifest_for_dependency_confusion(
    dependencies: dict[str, str],
    policy: Optional[ResolverPolicy] = None,
    evidence_for: Optional[Any] = None,
) -> dict[str, Any]:
    """Scan a manifest for dependency-confusion risk.

    A large/major version number is NEVER sufficient on its own. Each internal-style
    dependency is assessed through :func:`assess_dependency_confusion`; when the required
    evidence is missing (no declared private name, no allowed-registry policy, or no
    registry/resolution information), the entry is reported under
    ``insufficient_evidence`` and is NOT emitted as a finding.

    ``evidence_for`` is an optional ``callable(name, version) -> ConfusionEvidence``; when
    omitted, evidence is derived from the simulated registries (a name present in a registry
    IS resolution evidence, and an internal-style name IS a declared-private signal).
    """
    policy = policy or ResolverPolicy()
    findings: list[dict[str, Any]] = []
    insufficient: list[dict[str, Any]] = []

    def _default_evidence(name: str, version: str) -> ConfusionEvidence:
        declared = is_internal_style_name(name) or name in INTERNAL_REGISTRY
        resolved_known = name in INTERNAL_REGISTRY or name in PUBLIC_REGISTRY
        return ConfusionEvidence(
            private_name_declared=declared,
            allowed_registry_policy=True,  # an explicit ResolverPolicy is always in force
            resolution_evidence=resolved_known,
        )

    for name, version in dependencies.items():
        if not is_internal_style_name(name):
            continue
        ev = (
            evidence_for(name, version)
            if evidence_for is not None
            else _default_evidence(name, version)
        )
        assessment = assess_dependency_confusion(name, version, evidence=ev, policy=policy)
        if assessment["outcome"] == INSUFFICIENT_EVIDENCE:
            insufficient.append(assessment)
            continue
        if assessment["outcome"] not in ("safe_internal", "confused_public", "blocked_policy"):
            # unapplicable / unresolved: never reported as a confirmed finding
            insufficient.append(assessment)
            continue
        result = simulate_resolution(name, version, policy)
        severity = "high" if result.outcome == "confused_public" else "medium"
        findings.append(
            {
                "package": name,
                "requested_version": version,
                "outcome": result.outcome,
                "attacker_success": result.attacker_success,
                "severity": severity,
                "reason": result.reason,
                "resolved_source": result.resolved.source if result.resolved else None,
                "resolved_version": result.resolved.version if result.resolved else None,
                "simulated_effect": result.resolved.simulated_effect if result.resolved else None,
                "version_signal": assessment["version_signal"],
            }
        )

    return {
        "scanned": len(dependencies),
        "internal_style_dependencies": sum(1 for n in dependencies if is_internal_style_name(n)),
        "findings_count": len(findings),
        "findings": findings,
        "insufficient_evidence": insufficient,
        "insufficient_evidence_count": len(insufficient),
    }


def scan_manifest_for_dependency_confusion_project(
    dependencies: dict[str, str],
    context: Any,
) -> dict[str, Any]:
    """Dependency confusion against the ORGANISATION's declared internal names (project mode).

    A finding requires all three pieces of evidence: the name matches a namespace the
    organisation declared internal, a registry policy exists (the declaration itself), and the
    project lockfile records where the package resolved. Resolution from the public npm registry
    is a confirmed confusion. Without a lockfile record the entry is insufficient evidence; a
    high version number alone is never a finding.
    """
    findings: list[dict[str, Any]] = []
    insufficient: list[dict[str, Any]] = []
    internal = [n for n in dependencies if context.is_internal_name(n)]
    for name in internal:
        version = dependencies[name]
        public = context.resolved_from_public_registry(name)
        base = {
            "package": name,
            "requested_version": version,
            "version_signal": _major_version(version) >= 8,
        }
        if public is None:
            insufficient.append({
                **base,
                "outcome": INSUFFICIENT_EVIDENCE,
                "reason": "Declared internal name without a lockfile resolution record.",
            })
        elif public:
            resolved = str(context.lockfile[name].get("resolved"))
            findings.append({
                **base,
                "outcome": "confused_public",
                "attacker_success": True,
                "severity": "high",
                "reason": "Declared internal package name resolved from the public npm registry.",
                "resolved_source": "public",
                "resolved_url": resolved,
                "resolved_version": context.lockfile[name].get("version"),
                "simulated_effect": None,
            })
    return {
        "scanned": len(dependencies),
        "internal_style_dependencies": len(internal),
        "findings_count": len(findings),
        "findings": findings,
        "insufficient_evidence": insufficient,
        "insufficient_evidence_count": len(insufficient),
    }


def to_siem_event(finding: dict[str, Any], source: str = "demo-site") -> dict[str, Any]:
    return {
        "event_id": f"ATK2-{finding['package']}",
        "attack_type": "dependency_confusion",
        "severity": finding["severity"],
        "source": source,
        "package": finding["package"],
        "requested_version": finding["requested_version"],
        "resolved_source": finding["resolved_source"],
        "resolved_version": finding["resolved_version"],
        "attacker_success": finding["attacker_success"],
        "note": finding["reason"],
        "simulated_effect": finding["simulated_effect"],
        "recommendation": (
            "Pin private index precedence, block internal namespace from public sources, "
            "and enforce trusted package provenance."
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
