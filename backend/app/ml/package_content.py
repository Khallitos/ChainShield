"""Package-content features for the learned model (package layer).

A dependency-free port of the npm feature definitions of Ladisa et al., "On the Feasibility of
Cross-Language Detection of Malicious Packages in npm and PyPI" (ACSAC 2023), as released in
SAP's reference extractor (Apache-2.0; licence in ``resources/SAP_LICENSE_Apache-2.0.txt``).
The NPMStudy benchmark ships these features for every benign and malicious package, so the
model trained on that table can score a package whose features ChainShield computes here.

Safety: the package archive is read in memory. Nothing is unpacked to disk, installed or run.

Differences from the reference implementation are deliberate and documented:
  * URL counts used ``urlextract`` (TLD list download); they are not computed here and are not
    used by the model.
  * NLTK stop words are read from a vendored copy of the English list.
"""
from __future__ import annotations

import atexit
import base64
import io
import os
import json
import math
import re
import socket
import statistics
import tarfile
from collections import Counter
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
from pygments.lexers import JavascriptLexer, JsonLexer
from pygments.token import Token

_RES = Path(__file__).resolve().parent / "resources"

EXTENSIONS = [
    "bat", "bz2", "c", "cert", "conf", "cpp", "crt", "css", "csv", "deb", "erb", "gemspec", "gif",
    "gz", "h", "html", "ico", "ini", "jar", "java", "jpg", "js", "json", "key", "m4v", "markdown",
    "md", "pdf", "pem", "png", "ps", "py", "rb", "rpm", "rst", "sh", "svg", "toml", "ttf", "txt",
    "xml", "yaml", "yml", "eot", "exe", "jpeg", "properties", "sql", "swf", "tar", "woff", "woff2",
    "aac", "bmp", "cfg", "dcm", "dll", "doc", "flac", "flv", "ipynb", "m4a", "mid", "mkv", "mp3",
    "mp4", "mpg", "ogg", "otf", "pickle", "pkl", "psd", "pxd", "pxi", "pyc", "pyx", "r", "rtf",
    "so", "sqlite", "tif", "tp", "wav", "webp", "whl", "xcf", "xz", "zip", "mov", "wasm", "webm",
]

_B64 = re.compile(r"[a-zA-Z0-9=/\+]*")
_IP = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_STRING_TOKENS = (
    Token.Literal.String.Single, Token.Literal.String.Double, Token.Literal.String.Affix,
    Token.Literal.String.Backtick, Token.Literal.String.Char, Token.Literal.String.Delimiter,
    Token.Literal.String.Doc, Token.Literal.String.Escape, Token.Literal.String.Heredoc,
    Token.Literal.String.Interpol, Token.Literal.String.Other,
)
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_MEMBER_BYTES = 5 * 1024 * 1024


@lru_cache(maxsize=1)
def _dangerous_tokens() -> Tuple[str, ...]:
    return tuple(json.loads((_RES / "sap_dangerous_tokens.json").read_text(encoding="utf-8")))


@lru_cache(maxsize=1)
def _stopwords() -> frozenset:
    return frozenset((_RES / "nltk_stopwords_english.txt").read_text(encoding="utf-8").split())


def _is_base64(word: str) -> bool:
    try:
        raw = bytes(word, "ascii")
        decoded = " ".join(base64.b64decode(raw).decode("utf-8").split())
        return decoded.isprintable() and base64.b64encode(base64.b64decode(raw)) == raw
    except Exception:
        return False


def _count_base64(s: str) -> int:
    return sum(1 for w in dict.fromkeys(_B64.findall(s)) if len(w) > 1 and _is_base64(w))


def _count_ip(s: str) -> int:
    n = 0
    for w in dict.fromkeys(_IP.findall(s)):
        if len(w) > 6:
            try:
                socket.inet_aton(w.split(":")[0])
                n += 1
            except OSError:
                pass
    return n


def _count_dangerous(s: str) -> int:
    return sum(1 for t in _dangerous_tokens() if t in s)


def _gen4(value: str) -> str:
    out = []
    for c in str(value):
        out.append("d" if c.isnumeric() else "u" if c.isupper() else "l" if c.islower() else "s")
    return "".join(out)


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log(c / n, 4) for c in Counter(data).values())


def _heterogeneous(generalised: Iterable[str]) -> int:
    # The reference counts four upper/lower combinations that all require a digit and a symbol.
    return sum(1 for g in generalised if "d" in g and "s" in g)


def _read_text(data: bytes) -> Tuple[str, int, int]:
    text = data.decode("utf-8", errors="ignore")
    lines = sum(1 for _ in io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="ignore"))
    return text, lines, len(data) + 1


_KIND: Dict[object, int] = {}  # token type -> 0 operator, 1 punctuation, 2 name, 3 string, 4 other


def _kind(ttype) -> int:
    kind = _KIND.get(ttype)
    if kind is None:
        if ttype in Token.Operator:
            kind = 0
        elif ttype in Token.Punctuation:
            kind = 1
        elif ttype in Token.Name:
            kind = 2
        elif any(ttype in t for t in _STRING_TOKENS):
            kind = 3
        else:
            kind = 4
        _KIND[ttype] = kind
    return kind


def _lex(text: str, lexer) -> Tuple[List[str], List[str], List[str], List[str]]:
    buckets: Tuple[List[str], ...] = ([], [], [], [], [])
    for ttype, value in lexer.get_tokens(text):
        buckets[_kind(ttype)].append(value)
    return buckets[0], buckets[1], buckets[2], buckets[3]


def _file_record(data: bytes, lexer) -> Dict[str, object]:
    text, lines, size = _read_text(data)
    ops, punct, names, strs = _lex(text, lexer)
    record = {
        "words": len(text.split()),
        "lines": lines,
        "eq": ops.count("=") / size,
        "plus": ops.count("+") / size,
        "bracket": punct.count("[") / size,
        "base64": sum(_count_base64(s) for s in strs),
        "ip": sum(_count_ip(s) for s in strs),
        "dangerous": sum(_count_dangerous(s) for s in strs),
    }
    ids = [s.replace("'", "").replace('"', "") for s in names]
    stripped = [s.replace("'", "").replace('"', "") for s in strs]
    record["identifiers"] = " ".join(ids)
    # sorted: a set iterates in a per-process order, which would make the float statistics
    # below differ in the last digit between runs (and between pool workers).
    record["strings"] = " ".join(sorted(set(stripped) - _stopwords()))
    return record


def _stats(values: List[float]) -> Tuple[float, float, float, float]:
    """mean, max, sample std (0 when fewer than two files), q3, as the reference pandas code."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0
    std = float(statistics.stdev(values)) if len(values) > 1 else 0.0
    return float(np.mean(values)), float(max(values)), std, float(np.quantile(values, 0.75))


def _entropy_block(identifiers: List[str], strings: List[str], prefix: str) -> Dict[str, float]:
    out: Dict[str, float] = {}
    gid = [_gen4(x) for x in identifiers]
    gstr = [_gen4(x) for x in strings]
    for kind, gen in (("ID", gid), ("string", gstr)):
        ent = [_entropy(g) for g in gen]
        out[f"shannon mean {kind} {prefix}"] = float(statistics.mean(ent)) if ent else 0.0
        out[f"shannon std {kind} {prefix}"] = float(np.std(ent)) if len(ent) > 1 else 0.0
        out[f"shannon max {kind} {prefix}"] = float(max(ent)) if ent else 0.0
        out[f"shannon q3 {kind} {prefix}"] = float(np.quantile(ent, 0.75)) if ent else 0.0
    out[f"homogeneous identifiers in {prefix}"] = float(sum(1 for e in (_entropy(g) for g in gid) if e == 0))
    out[f"homogeneous strings in {prefix}"] = float(sum(1 for e in (_entropy(g) for g in gstr) if e == 0))
    out[f"heterogeneous strings in {prefix}"] = float(_heterogeneous(gstr))
    het_id_key = "heteregeneous identifiers in " + prefix
    out[het_id_key] = float(_heterogeneous(gid))
    return out


# Lexing is pure Python and dominates the cost: a large package (next: ~40 MB archive) takes
# minutes on one core. Files are independent, so above this much JavaScript they are lexed in a
# process pool. Every feature is a sum or an order-free statistic over per-file records, so the
# result is identical to the sequential computation.
PARALLEL_JS_BYTES = 2 * 1024 * 1024
_POOL = None


def _js_record(data: bytes) -> Dict[str, object]:
    return _file_record(data, JavascriptLexer(stripnl=False, ensurenl=False))


def _pool():
    global _POOL
    if _POOL is None:
        from concurrent.futures import ProcessPoolExecutor

        _POOL = ProcessPoolExecutor(max_workers=max(1, (os.cpu_count() or 2) - 1))
        atexit.register(_POOL.shutdown, wait=False, cancel_futures=True)
    return _POOL


def _js_records(blobs: List[bytes]) -> List[Dict[str, object]]:
    if sum(len(b) for b in blobs) < PARALLEL_JS_BYTES or len(blobs) < 2:
        lexer = JavascriptLexer(stripnl=False, ensurenl=False)
        return [_file_record(b, lexer) for b in blobs]
    try:
        return list(_pool().map(_js_record, blobs, chunksize=8))
    except Exception:  # pool unavailable (e.g. restricted environment): same result, slower
        lexer = JavascriptLexer(stripnl=False, ensurenl=False)
        return [_file_record(b, lexer) for b in blobs]


def features_from_files(files: Iterable[Tuple[str, bytes]]) -> Dict[str, float]:
    """Compute SAP npm features from (relative path, bytes) pairs of ONE package."""
    json_records = []
    js_blobs: List[bytes] = []
    ext_counts: Counter = Counter()
    json_lexer = JsonLexer(stripnl=False, ensurenl=False)
    for path, data in files:
        suffix = PurePosixPath(path).suffix
        if suffix and suffix[1:] in EXTENSIONS:
            ext_counts[suffix] += 1
        if suffix == ".js":
            js_blobs.append(data)
        elif PurePosixPath(path).name == "package.json":
            json_records.append(_file_record(data, json_lexer))
    js_records = _js_records(js_blobs)

    f: Dict[str, float] = {}
    for tag, recs in (("x", js_records), ("y", json_records)):
        f[f"Number of words_{tag}"] = float(sum(r["words"] for r in recs))
        f[f"lines_{tag}"] = float(sum(r["lines"] for r in recs))
        f[f"base64_{tag}"] = float(sum(r["base64"] for r in recs))
        f[f"IP_{tag}"] = float(sum(r["ip"] for r in recs))
        f[f"sospicious token_{tag}"] = float(sum(r["dangerous"] for r in recs))
    for key, col in (("plus", "plus ratio"), ("eq", "eq ratio"), ("bracket", "bracket ratio")):
        mean, mx, std, q3 = _stats([r[key] for r in js_records])
        f[f"{col} mean"], f[f"{col} max"], f[f"{col} std"], f[f"{col} q3"] = mean, mx, std, q3
    for ext in EXTENSIONS:
        f["." + ext] = float(ext_counts.get("." + ext, 0))
    f["repository"] = 1.0

    js_ids = " ".join(r["identifiers"] for r in js_records).split()
    js_strs = " ".join(r["strings"] for r in js_records).split()
    md_ids = " ".join(r["identifiers"] for r in json_records).split()
    md_strs = " ".join(r["strings"] for r in json_records).split()
    f["presence of installation script"] = float(
        any(k in md_ids for k in ("postinstall", "preinstall", "install"))
    )
    f.update(_entropy_block(js_ids, js_strs, "source code"))
    f.update(_entropy_block(md_ids, md_strs, "metadata"))
    return f


def read_npm_tarball(data: bytes) -> List[Tuple[str, bytes]]:
    """Regular-file members of an npm .tgz, read in memory with size limits (no extraction)."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("package archive exceeds size limit")
    out: List[Tuple[str, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for member in tar:
            if not member.isreg() or member.size > MAX_MEMBER_BYTES:
                continue
            fh = tar.extractfile(member)
            if fh is not None:
                out.append((member.name, fh.read()))
    return out


def features_from_tarball(data: bytes) -> Dict[str, float]:
    return features_from_files(read_npm_tarball(data))


def feature_vector(features: Dict[str, float], columns: List[str]) -> List[float]:
    return [float(features.get(c, 0.0)) for c in columns]


__all__ = [
    "EXTENSIONS",
    "features_from_files",
    "features_from_tarball",
    "read_npm_tarball",
    "feature_vector",
]
