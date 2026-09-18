"""Step 0: download the pinned public inputs into research/raw/ (no scraping; three published sources).

1. NPMStudy replication package (figshare DOI 10.6084/m9.figshare.31869370, CC BY 4.0)
   - the 88 MB file in full (labels, tool outputs, unpacked sample packages)
   - from the 4.8 GB file ONLY the feature/label tables and the SAP extractor licence, read with
     HTTP range requests; the malware archives in that file are never downloaded
2. GuardDog top-8,000 npm package list (Apache-2.0) at a pinned commit
3. Workflow scanner study data (arXiv:2601.14455) at a pinned commit: workflow contents and the
   normalised per-workflow scanner findings (no licence stated; downloaded, not redistributed)

Every file is checked against the digest recorded below.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"

NPMSTUDY_SMALL = ("https://ndownloader.figshare.com/files/63179326", "be67198a63e059ec7a123c356784db6f")
NPMSTUDY_LARGE = ("https://ndownloader.figshare.com/files/66774704", 4816949651)
TABLES = {
    "NPMStudy/Tools/sap/scripts/feature_extraction/benign_npm_feature_extracted.csv":
        "deff59a9d5a75c5b4e0f4cc03fdfed506878206b400b3564ff829281feadd923",
    "NPMStudy/Tools/sap/scripts/feature_extraction/malware_npm_feature_extracted.csv":
        "999e6fab483e2cee8d56746a7551c1669148db4dc0f5581d3413519db5a64c2e",
    "NPMStudy/Experiment/RQ2/statistic/behavior_detection/data/package_version_labels.csv":
        "182c9c1d863511460c0bd38f9c37469cd0a14947d9051ef43b6baa1699d56913",
}
GUARDDOG = ("https://raw.githubusercontent.com/DataDog/guarddog/632031f5b58df3a46b22d1daa516954b4170e9bd/"
            "guarddog/analyzer/metadata/resources/top_npm_packages.json",
            # SHA-256 of the package list only: the file also carries a `downloaded_timestamp`
            # that differs between published copies, so a digest of the whole file cannot be pinned.
            "8c6bfb02cee073aa2c0490e7269d6c8e7d0a97a911ab44c1fb14947d39da293b")
WORKFLOW_REPO = "https://github.com/sparkrew/github-actions-security.git"
WORKFLOW_COMMIT = "a673bc065d587e46de2a54a43547974a13b581b4"
WORKFLOW_METADATA_SHA256 = "af2ac3f66555e7eb95251908064f35ba89c49c096d7bd6a21c6caca6f5a9afdf"


def digest(path: Path, algo: str) -> str:
    h = hashlib.new(algo)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as resp, dest.open("wb") as out:
        shutil.copyfileobj(resp, out)


def byte_range(url: str, start: int, end: int) -> bytes:
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def remote_zip_members(url: str, size: int, wanted: set[str]) -> dict[str, bytes]:
    """Selected members of a remote zip via its central directory (zip64-aware)."""
    tail = byte_range(url, size - 65536, size - 1)
    i = tail.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack("<II", tail[i + 12:i + 20])
    j = tail.rfind(b"PK\x06\x06")
    if j != -1:
        cd_size, cd_off = struct.unpack("<QQ", tail[j + 40:j + 56])
    cd = byte_range(url, cd_off, cd_off + cd_size - 1)
    found: dict[str, bytes] = {}
    p = 0
    while p + 46 <= len(cd) and cd[p:p + 4] == b"PK\x01\x02":
        method = struct.unpack("<H", cd[p + 10:p + 12])[0]
        csize, usize = struct.unpack("<II", cd[p + 20:p + 28])
        fl, el, cl = struct.unpack("<HHH", cd[p + 28:p + 34])
        off = struct.unpack("<I", cd[p + 42:p + 46])[0]
        name = cd[p + 46:p + 46 + fl].decode("utf-8", "replace")
        extra = cd[p + 46 + fl:p + 46 + fl + el]
        if name in wanted:
            q = 0
            while q + 4 <= len(extra):
                hid, hl = struct.unpack("<HH", extra[q:q + 4])
                if hid == 1:
                    vals, k = extra[q + 4:q + 4 + hl], 0
                    if usize == 0xFFFFFFFF:
                        usize = struct.unpack("<Q", vals[k:k + 8])[0]; k += 8
                    if csize == 0xFFFFFFFF:
                        csize = struct.unpack("<Q", vals[k:k + 8])[0]; k += 8
                    if off == 0xFFFFFFFF:
                        off = struct.unpack("<Q", vals[k:k + 8])[0]
                q += 4 + hl
            header = byte_range(url, off, off + 29)
            nl, xl = struct.unpack("<HH", header[26:30])
            data = byte_range(url, off + 30 + nl + xl, off + 30 + nl + xl + csize - 1)
            found[name] = zlib.decompress(data, -15) if method == 8 else data
        p += 46 + fl + el + cl
    return found


def check(path: Path, expected: str, algo: str = "sha256") -> None:
    actual = digest(path, algo)
    if actual != expected:
        sys.exit(f"digest mismatch for {path}: {actual} != {expected}")
    print(f"  ok  {path.relative_to(ROOT)}")


def check_package_list(path: Path, expected: str) -> None:
    packages = json.loads(path.read_text(encoding="utf-8"))["packages"]
    actual = hashlib.sha256(json.dumps(packages, separators=(",", ":")).encode()).hexdigest()
    if actual != expected:
        sys.exit(f"package-list digest mismatch for {path}: {actual} != {expected}")
    print(f"  ok  {path.relative_to(ROOT)} ({len(packages)} entries)")


def main() -> None:
    small = RAW / "NPMStudy_88MB.zip"
    if not small.is_file():
        print("downloading NPMStudy (88 MB) ...")
        download(NPMSTUDY_SMALL[0], small)
    check(small, NPMSTUDY_SMALL[1], "md5")

    tables = RAW / "npmstudy_tables"
    missing = {k: v for k, v in TABLES.items() if not (tables / Path(k).name).is_file()}
    if missing:
        print("reading feature tables from the large NPMStudy file (range requests only) ...")
        for name, data in remote_zip_members(*NPMSTUDY_LARGE, set(missing)).items():
            tables.mkdir(parents=True, exist_ok=True)
            (tables / Path(name).name).write_bytes(data)
    for name, sha in TABLES.items():
        check(tables / Path(name).name, sha)

    top = RAW / "guarddog_top_npm_packages.json"
    if not top.is_file():
        download(GUARDDOG[0], top)
    check_package_list(top, GUARDDOG[1])

    wf = RAW / "workflows"
    if not (wf / "workflow_metadata.csv").is_file() or len(list((wf / "normalized").glob("*.json"))) < 2722:
        print("fetching workflow study data at pinned commit (blobs of two folders only) ...")
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
            subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", WORKFLOW_REPO, str(repo)],
                           check=True)
            run("fetch", "-q", "origin", WORKFLOW_COMMIT)
            listing = run("ls-tree", "-r", WORKFLOW_COMMIT, "dataset/workflow_metadata.csv",
                          "results/normalized_workflows").stdout.decode().splitlines()
            (wf / "normalized").mkdir(parents=True, exist_ok=True)
            for line in listing:
                meta, path = line.split("\t", 1)
                sha = meta.split()[2]
                blob = run("cat-file", "-p", sha).stdout
                target = wf / "workflow_metadata.csv" if path.endswith("workflow_metadata.csv") \
                    else wf / "normalized" / Path(path).name
                target.write_bytes(blob)
    check(wf / "workflow_metadata.csv", WORKFLOW_METADATA_SHA256)
    print(f"  ok  {len(list((wf / 'normalized').glob('*.json')))} normalised workflow findings")


if __name__ == "__main__":
    main()
