"""Grounding check for generated reports.

Every identifier-like token in a report (CVE/GHSA IDs, URLs, semantic versions and npm package
names) must occur in the evidence the report was generated from. Tokens that do not are listed
as ungrounded and the report is labelled accordingly; the check never changes a decision.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List

_PATTERNS = {
    "advisory_id": re.compile(r"\b(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[0-9a-z]{4}){3})\b", re.I),
    "url": re.compile(r"https?://[^\s\"'<>)\]]+"),
    "version": re.compile(r"\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\b"),
    "scoped_package": re.compile(r"@[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*"),
}


def _texts(report: Dict[str, Any]) -> Iterable[str]:
    for key in ("summary", "training_platform_note", "business_impact"):
        if isinstance(report.get(key), str):
            yield report[key]
    for key in ("technical_impact", "recommended_actions"):
        for item in report.get(key) or []:
            if isinstance(item, str):
                yield item


def check_grounding(report: Dict[str, Any], evidence: Dict[str, Any]) -> Dict[str, Any]:
    haystack = json.dumps(evidence, default=str).lower()
    ungrounded: List[Dict[str, str]] = []
    checked = 0
    for text in _texts(report):
        for kind, pattern in _PATTERNS.items():
            for match in pattern.findall(text):
                token = match if isinstance(match, str) else match[0]
                checked += 1
                if token.lower().rstrip(".,;") not in haystack:
                    ungrounded.append({"kind": kind, "token": token})
    return {"identifiers_checked": checked, "ungrounded": ungrounded, "grounded": not ungrounded}


__all__ = ["check_grounding"]
