"""Build trusted package graph from lockfiles and registry policy (not manual lists)."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Project root: backend/app/services -> ../../../..
_PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_LOCKFILE_PATHS = [
    _PROJECT_ROOT / "demo-site" / "package-lock.json",
    _PROJECT_ROOT / "demo-site" / "lab-victim-dep-confusion" / "safe" / "package-lock.json",
    _PROJECT_ROOT / "demo-site" / "lab-victim-typo-only" / "package-lock.json",
]

DEFAULT_OUTPUT = _PROJECT_ROOT / "data" / "trusted" / "baseline.json"

INTERNAL_NAMESPACE_PATTERNS = [
    r"^corp-internal-",
    r"^@corp/",
]

CANONICAL_LAB_PACKAGES = [
    "training-ledger",
    "corp-internal-ledger-api",
    "corp-internal-ledger-sync",
]


def _parse_node_module_name(path_key: str) -> Optional[str]:
    """Extract npm package name from lockfile key like node_modules/@scope/pkg."""
    if not path_key.startswith("node_modules/"):
        return None
    remainder = path_key[len("node_modules/") :]
    if remainder.startswith("@"):
        parts = remainder.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None
    return remainder.split("/")[0]


def _registry_from_resolved(resolved: Optional[str]) -> str:
    if not resolved:
        return "unknown"
    if resolved.startswith("file:") or "packages/" in resolved:
        return "file"
    if "registry.npmjs.org" in resolved:
        return "public"
    if resolved.startswith("http"):
        return "custom"
    return "link"


def parse_npm_lockfile(lock_path: Path) -> Dict[str, Dict[str, Any]]:
    """Return {package_name: {version, source, resolved, integrity}} from npm lock v2/v3."""
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = data.get("packages") or {}
    out: Dict[str, Dict[str, Any]] = {}

    root = packages.get("", {})
    for name, ver_spec in (root.get("dependencies") or {}).items():
        out.setdefault(name, {"version": _strip_version_prefix(str(ver_spec)), "source": "root_manifest"})

    for key, meta in packages.items():
        name = _parse_node_module_name(key)
        if not name:
            continue
        resolved = meta.get("resolved")
        version = meta.get("version") or _linked_version(lock_path, resolved)
        entry = {
            "version": version or out.get(name, {}).get("version", "*"),
            "source": _registry_from_resolved(resolved),
            "resolved": resolved,
            "integrity": meta.get("integrity"),
            "from_lockfile": str(lock_path.relative_to(_PROJECT_ROOT)),
        }
        if name in out:
            out[name].update({k: v for k, v in entry.items() if v is not None})
        else:
            out[name] = entry

    return out


def _linked_version(lock_path: Path, resolved: Optional[str]) -> Optional[str]:
    """Version of a locally linked package (`file:` folder), read from its own package.json.

    npm records a link without a version; the trusted version is the one the linked folder
    declares, not the folder path.
    """
    if not resolved or resolved.startswith("http") or resolved.endswith((".tgz", ".tar.gz")):
        return None
    target = (lock_path.parent / resolved.removeprefix("file:")).resolve() / "package.json"
    try:
        return json.loads(target.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError):
        return None


def _strip_version_prefix(spec: str) -> str:
    return spec.removeprefix("^").removeprefix("~").removeprefix("file:")


def build_baseline(
    lockfile_paths: Optional[List[Path]] = None,
    baseline_id: str = "default",
) -> Dict[str, Any]:
    paths = lockfile_paths or [p for p in DEFAULT_LOCKFILE_PATHS if p.is_file()]
    if not paths:
        raise FileNotFoundError("No lockfiles found to build trust baseline")

    trusted: Dict[str, Dict[str, Any]] = {}
    sources: List[str] = []

    for path in paths:
        sources.append(str(path.relative_to(_PROJECT_ROOT)))
        for name, meta in parse_npm_lockfile(path).items():
            existing = trusted.get(name, {})
            merged = {**existing, **meta}
            merged["trusted"] = True
            trusted[name] = merged

    for canonical in CANONICAL_LAB_PACKAGES:
        trusted.setdefault(
            canonical,
            {
                "version": trusted.get(canonical, {}).get("version", "1.0.0"),
                "source": "canonical_lab",
                "trusted": True,
            },
        )

    return {
        "baseline_id": baseline_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": sources,
        "trusted_packages": trusted,
        "canonical_names": sorted(set(CANONICAL_LAB_PACKAGES + list(trusted.keys()))),
        "internal_namespace_patterns": INTERNAL_NAMESPACE_PATTERNS,
        "registry_policy": {
            "prefer_internal_for_corp_names": True,
            "block_public_fallback_for_internal_names": True,
        },
    }


def save_baseline(
    output_path: Optional[Path] = None,
    lockfile_paths: Optional[List[Path]] = None,
) -> Path:
    out_path = output_path or DEFAULT_OUTPUT
    out_path.parent.mkdir(parents=True, exist_ok=True)
    baseline = build_baseline(lockfile_paths=lockfile_paths)
    out_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    return out_path


def load_baseline(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or DEFAULT_OUTPUT
    if not p.is_file():
        save_baseline(output_path=p)
    return json.loads(p.read_text(encoding="utf-8"))


def matches_internal_namespace(name: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if re.match(pat, name):
            return True
    return False
