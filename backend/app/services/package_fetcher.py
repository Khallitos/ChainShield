"""Fetch a published npm package archive for read-only content analysis.

The archive is downloaded from the public npm registry, checked against the registry's
``dist.integrity`` (SHA-512) or ``dist.shasum`` (SHA-1), and returned as bytes. It is never
unpacked to disk, installed or executed. Set ``CHAINSHIELD_PACKAGE_FETCH=off`` to disable
network access (the package model then reports itself unavailable).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import tarfile
from functools import lru_cache
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import quote

import httpx

REGISTRY = os.getenv("CHAINSHIELD_NPM_REGISTRY", "https://registry.npmjs.org")
TIMEOUT = 20.0
MAX_BYTES = 50 * 1024 * 1024
_CACHE: Dict[Tuple[str, str], bytes] = {}

Fetcher = Callable[[str, str], Optional[bytes]]


def fetch_enabled() -> bool:
    return os.getenv("CHAINSHIELD_PACKAGE_FETCH", "on").lower() not in ("off", "0", "false")


def _verify(data: bytes, dist: dict) -> bool:
    integrity = str(dist.get("integrity") or "")
    if integrity.startswith("sha512-"):
        return base64.b64encode(hashlib.sha512(data).digest()).decode() == integrity[len("sha512-"):]
    shasum = dist.get("shasum")
    return bool(shasum) and hashlib.sha1(data).hexdigest() == shasum


# ── version ranges ───────────────────────────────────────────────────────────
# A package.json usually declares ranges ("^4", "~1.2.3", "5.x"). Without a lockfile the
# package that `npm install` would pick is the highest published, non-prerelease version that
# satisfies the range; that exact version is the one scored.

_EXACT = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$")
_PARTIAL = re.compile(r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?$")
_RESOLVED: Dict[Tuple[str, str], Optional[str]] = {}


def _triple(v: str) -> Optional[Tuple[int, int, int]]:
    m = _EXACT.match(v)
    if not m or "-" in v.split("+", 1)[0]:
        return None  # prereleases are never chosen for a range
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _bounds(comparator: str) -> Optional[Tuple[Tuple[int, int, int], Tuple[int, int, int]]]:
    """[low, high) for one caret/tilde/partial/exact comparator; None if unsupported."""
    op = comparator[0] if comparator[:1] in ("^", "~") else ""
    body = comparator[len(op):].strip().lstrip("=")
    m = _PARTIAL.match(body)
    if not m:
        return None
    parts = [None if p is None or p in "xX*" else int(p) for p in m.groups()]
    major, minor, patch = parts
    top = (10**9, 0, 0)
    if major is None:
        return (0, 0, 0), top
    if minor is None:
        return (major, 0, 0), (major + 1, 0, 0)
    if patch is None:
        if op == "^" and major == 0:
            return (0, minor, 0), (0, minor + 1, 0)
        if op == "^":
            return (major, minor, 0), (major + 1, 0, 0)
        return (major, minor, 0), (major, minor + 1, 0)
    low = (major, minor, patch)
    if op == "^":
        if major > 0:
            return low, (major + 1, 0, 0)
        if minor > 0:
            return low, (0, minor + 1, 0)
        return low, (0, 0, patch + 1)
    if op == "~":
        return low, (major, minor + 1, 0)
    return low, (major, minor, patch + 1)


def _satisfies(version: Tuple[int, int, int], spec: str) -> Optional[bool]:
    """True/False for supported ranges (incl. ``a || b`` and ``>=a <b``); None if unsupported."""
    for alternative in spec.split("||"):
        ok = True
        tokens = alternative.split()
        if not tokens:
            return None
        for tok in tokens:
            cmp_ = re.match(r"^(>=|<=|>|<)\s*(.+)$", tok)
            if cmp_:
                ref = _triple(cmp_.group(2)) or (_bounds(cmp_.group(2)) or (None,))[0]
                if ref is None:
                    return None
                op = cmp_.group(1)
                ok &= {">=": version >= ref, "<=": version <= ref, ">": version > ref, "<": version < ref}[op]
            else:
                b = _bounds(tok)
                if b is None:
                    return None
                ok &= b[0] <= version < b[1]
        if ok:
            return True
    return False


def resolve_npm_version(name: str, spec: str) -> Optional[str]:
    """The exact version `npm install` would pick for ``spec``; the spec itself if already exact."""
    spec = str(spec).strip()
    if _EXACT.match(spec.lstrip("=")):
        return spec.lstrip("=v")
    if not fetch_enabled():
        return None
    key = (name, spec)
    if key in _RESOLVED:
        return _RESOLVED[key]
    chosen: Optional[str] = None
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
            resp = client.get(
                f"{REGISTRY}/{quote(name, safe='@')}",
                headers={"Accept": "application/vnd.npm.install-v1+json"},
            )
        if resp.status_code == 200:
            doc = resp.json()
            latest = (doc.get("dist-tags") or {}).get("latest")
            candidates = [(t, v) for v in (doc.get("versions") or {}) if (t := _triple(v))]
            # npm prefers the "latest" tag when it satisfies the range.
            lt = _triple(latest) if latest else None
            if lt and _satisfies(lt, spec or "*"):
                chosen = latest
            else:
                matching = [(t, v) for t, v in candidates if _satisfies(t, spec or "*")]
                if matching:
                    chosen = max(matching)[1]
    except (httpx.HTTPError, ValueError):
        return None  # transient: do not remember the failure
    _RESOLVED[key] = chosen
    return chosen


def fetch_npm_tarball(name: str, version: str) -> Optional[bytes]:
    """Integrity-checked archive bytes for ``name@version`` (a range is resolved first), or None."""
    if not fetch_enabled():
        return None
    version = resolve_npm_version(name, version)
    if version is None:
        return None
    key = (name, version)
    if key in _CACHE:
        return _CACHE[key]
    try:
        with httpx.Client(timeout=TIMEOUT, follow_redirects=True) as client:
            meta = client.get(f"{REGISTRY}/{quote(name, safe='@')}/{quote(version)}")
            if meta.status_code != 200:
                return None
            dist = meta.json().get("dist") or {}
            url = dist.get("tarball")
            if not url:
                return None
            resp = client.get(url)
            if resp.status_code != 200 or len(resp.content) > MAX_BYTES:
                return None
            if not _verify(resp.content, dist):
                return None
    except (httpx.HTTPError, ValueError):
        return None
    if len(resp.content) <= 5 * 1024 * 1024:  # large archives are scored once, then the score is cached
        _CACHE[key] = resp.content
    return resp.content


# ── laboratory fixtures ──────────────────────────────────────────────────────
# The lab scenarios (ATK1/ATK2) use packages that exist only in demo-site/packages, never on
# the public registry. In lab mode their archive is built in memory from those files (read as
# bytes, never installed or run), matched by exact name AND version.

LAB_PACKAGES_DIR = Path(__file__).resolve().parents[3] / "demo-site" / "packages"


@lru_cache(maxsize=1)
def _lab_index() -> Dict[Tuple[str, str], Path]:
    index: Dict[Tuple[str, str], Path] = {}
    if not LAB_PACKAGES_DIR.is_dir():
        return index
    for pkg_dir in LAB_PACKAGES_DIR.iterdir():
        manifest = pkg_dir / "package.json"
        if not manifest.is_file():
            continue
        try:
            meta = json.loads(manifest.read_text(encoding="utf-8"))
        except ValueError:
            continue
        index[(str(meta.get("name")), str(meta.get("version")))] = pkg_dir
    return index


def lab_fixture_tarball(name: str, version: str) -> Optional[bytes]:
    """An in-memory npm-style archive of a laboratory fixture package, or None."""
    wanted = str(version).lstrip("^~=v ")
    pkg_dir = _lab_index().get((name, wanted))
    if pkg_dir is None and wanted in ("", "*", "latest"):
        same_name = [d for (n, _v), d in _lab_index().items() if n == name]
        pkg_dir = same_name[0] if len(same_name) == 1 else None
    if pkg_dir is None:
        return None
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(p for p in pkg_dir.rglob("*") if p.is_file()):
            tar.add(path, arcname=f"package/{path.relative_to(pkg_dir).as_posix()}", recursive=False)
    return buf.getvalue()


def lab_first_fetcher(name: str, version: str) -> Optional[bytes]:
    """Lab mode: the laboratory fixture if one matches, otherwise the public registry."""
    return lab_fixture_tarball(name, version) or fetch_npm_tarball(name, version)


__all__ = [
    "Fetcher",
    "fetch_enabled",
    "fetch_npm_tarball",
    "lab_first_fetcher",
    "lab_fixture_tarball",
    "resolve_npm_version",
]
