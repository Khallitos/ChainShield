#!/usr/bin/env python3
"""Copy a gate fixture project into a scratch dir, making `file:` resolved paths ABSOLUTE.

Used by demo-cases.sh so a bare `npm ci` CONTROL run can execute OUTSIDE the original
repository tree (never installing into demo-site/). Synthetic benign fixtures only; this
helper runs no package script and touches no network.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


def _absolutise(tail: str, src: Path) -> str:
    p = Path(tail)
    if not p.is_absolute():
        p = src / tail
    return "file:" + p.resolve().as_posix()


def main(src: str, dst: str) -> int:
    src_p = Path(src).resolve()
    dst_p = Path(dst).resolve()
    if dst_p.exists():
        shutil.rmtree(dst_p)
    dst_p.mkdir(parents=True)

    pkg = json.loads((src_p / "package.json").read_text(encoding="utf-8"))
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        d = pkg.get(key)
        if isinstance(d, dict):
            for name, spec in list(d.items()):
                if isinstance(spec, str) and spec.startswith("file:"):
                    d[name] = _absolutise(spec[len("file:"):], src_p)
    (dst_p / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")

    lock = json.loads((src_p / "package-lock.json").read_text(encoding="utf-8"))
    for _node, meta in (lock.get("packages") or {}).items():
        if isinstance(meta, dict):
            res = meta.get("resolved")
            if isinstance(res, str) and res.startswith("file:"):
                meta["resolved"] = _absolutise(res[len("file:"):], src_p)
    (dst_p / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n",
                                             encoding="utf-8")
    print(str(dst_p))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
