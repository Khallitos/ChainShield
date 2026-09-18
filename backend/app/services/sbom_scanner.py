"""Parse CycloneDX and SPDX SBOM documents into dependency maps."""
from __future__ import annotations

from typing import Any, Dict, List, Tuple


def parse_sbom(format_name: str, sbom: Dict[str, Any]) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    """
    Return (dependencies map, raw component list).
    Raises ValueError on unsupported or empty SBOM.
    """
    fmt = format_name.strip().lower()
    if fmt == "cyclonedx":
        return _parse_cyclonedx(sbom)
    if fmt == "spdx":
        return _parse_spdx(sbom)
    raise ValueError(f"Unsupported SBOM format: {format_name!r}. Use cyclonedx or spdx.")


def _parse_cyclonedx(sbom: Dict[str, Any]) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    components = sbom.get("components") or []
    if not components:
        raise ValueError("CycloneDX SBOM missing components array")
    deps: Dict[str, str] = {}
    raw: List[Dict[str, Any]] = []
    for comp in components:
        name = comp.get("name")
        if not name:
            continue
        version = comp.get("version") or "*"
        deps[name] = str(version)
        raw.append(comp)
    if not deps:
        raise ValueError("CycloneDX SBOM contains no named components")
    return deps, raw


def _parse_spdx(sbom: Dict[str, Any]) -> Tuple[Dict[str, str], List[Dict[str, Any]]]:
    packages = sbom.get("packages") or []
    if not packages:
        raise ValueError("SPDX SBOM missing packages array")
    deps: Dict[str, str] = {}
    raw: List[Dict[str, Any]] = []
    for pkg in packages:
        name = pkg.get("name")
        if not name or name == "NOASSERTION":
            continue
        version = pkg.get("versionInfo") or "*"
        deps[name] = str(version)
        raw.append(pkg)
    if not deps:
        raise ValueError("SPDX SBOM contains no named packages")
    return deps, raw
