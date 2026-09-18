"""Google Gemini: grounded block reports (interpreter, not decision engine)."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import GEMINI_API_BASE, GEMINI_API_KEY, GEMINI_MODEL
from app.services.report_grounding import check_grounding

_REPORT_CACHE: Dict[str, Dict[str, Any]] = {}

SYSTEM_INSTRUCTION = """You are a supply chain security advisor for a team building a training management system.
You explain block decisions produced by a Hybrid ML + rule engine. You do NOT make block/allow decisions.

Rules:
- Use ONLY facts present in the provided JSON evidence.
- Do not invent CVE IDs, package names, versions, or registry URLs not in the evidence.
- Frame impact for developers working on a training platform (modules, locale bundles, finance training helpers).
- Be concise and actionable.
- Write plain sentences. Never use em dashes or en dashes; use commas, colons or full stops.

Respond with valid JSON only (no markdown fences) using this schema:
{
  "summary": "2-3 sentences for the team lead",
  "training_platform_note": "1-2 sentences tying the risk to training-mgmt development context",
  "business_impact": "1-2 sentences on organizational risk if this had been allowed",
  "technical_impact": ["bullet 1", "bullet 2", "..."],
  "recommended_actions": ["action 1", "action 2", "..."]
}
"""


def gemini_configured() -> bool:
    return bool(GEMINI_API_KEY)


def _cache_key(package: str, payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(f"{package}:{blob}".encode()).hexdigest()[:24]


def _without_dashes(value: Any) -> Any:
    """Model text sometimes still contains em/en dashes; the dashboard shows none."""
    if isinstance(value, str):
        return value.replace(", ", ", ").replace("-", ", ").replace("-", "-")
    if isinstance(value, list):
        return [_without_dashes(v) for v in value]
    if isinstance(value, dict):
        return {k: _without_dashes(v) for k, v in value.items()}
    return value


def _parse_json_response(text: str) -> Dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    return {
        "summary": raw[:800] if raw else "Report unavailable.",
        "training_platform_note": "",
        "business_impact": "",
        "technical_impact": [],
        "recommended_actions": [],
    }


def _fallback_report(evidence: Dict[str, Any]) -> Dict[str, Any]:
    engine = evidence.get("engine") or {}
    reasons = engine.get("top_reasons") or []
    fixes = engine.get("recommended_fixes") or []
    return {
        "summary": evidence.get("primary_reason")
        or (reasons[0].get("description") if reasons else "Blocked by hybrid policy."),
        "training_platform_note": (
            "When adding training helper packages, verify names against your internal ledger/module registry."
        ),
        "business_impact": "A malicious dependency could compromise developer machines and CI secrets.",
        "technical_impact": [r.get("description", "") for r in reasons[:4] if r.get("description")],
        "recommended_actions": fixes[:5],
        "source": "fallback",
        "model": None,
    }


async def generate_block_report(
    *,
    package: str,
    version: str = "*",
    attack_type: Optional[str] = None,
    source: Optional[str] = None,
    engine: Optional[Dict[str, Any]] = None,
    primary_reason: Optional[str] = None,
    canonical: Optional[str] = None,
    hostname: Optional[str] = None,
    cwd: Optional[str] = None,
    audience: str = "developer",
) -> Dict[str, Any]:
    """Generate a grounded narrative report from hybrid engine evidence."""
    evidence = {
        "package": package,
        "version": version,
        "attack_type": attack_type,
        "source": source,
        "primary_reason": primary_reason,
        "canonical": canonical,
        "hostname": hostname,
        "cwd": cwd,
        "audience": audience,
        "engine": engine or {},
    }

    key = _cache_key(package, evidence)
    if key in _REPORT_CACHE:
        cached = dict(_REPORT_CACHE[key])
        cached["cached"] = True
        return cached

    if not GEMINI_API_KEY:
        report = _fallback_report(evidence)
        report["cached"] = False
        report["gemini_available"] = False
        report["grounding"] = check_grounding(report, evidence)
        return report

    user_prompt = (
        "Write a block explanation report from this hybrid engine evidence:\n\n"
        f"{json.dumps(evidence, indent=2, default=str)}"
    )

    url = f"{GEMINI_API_BASE}/models/{GEMINI_MODEL}:generateContent"
    body = {
        "system_instruction": {"parts": [{"text": SYSTEM_INSTRUCTION}]},
        "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
        "generationConfig": {
            "temperature": 0.25,
            "responseMimeType": "application/json",
        },
    }

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            # The key travels in a header, never in the URL (URLs end up in proxy and server logs).
            resp = await client.post(
                url,
                headers={"x-goog-api-key": GEMINI_API_KEY},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()
        candidates = data.get("candidates") or []
        parts = (candidates[0].get("content") or {}).get("parts") or [] if candidates else []
        text = parts[0].get("text", "") if parts else ""
        parsed = _parse_json_response(text)
        parsed = _without_dashes(parsed)
        report = {
            "summary": parsed.get("summary") or primary_reason or "",
            "training_platform_note": parsed.get("training_platform_note") or "",
            "business_impact": parsed.get("business_impact") or "",
            "technical_impact": list(parsed.get("technical_impact") or [])[:8],
            "recommended_actions": list(parsed.get("recommended_actions") or [])[:8],
            "source": "gemini",
            "model": GEMINI_MODEL,
            "gemini_available": True,
            "cached": False,
        }
        report["grounding"] = check_grounding(report, evidence)
        _REPORT_CACHE[key] = report
        return report
    except Exception as exc:
        fallback = _fallback_report(evidence)
        fallback["source"] = "fallback"
        fallback["gemini_available"] = True
        fallback["gemini_error"] = str(exc)[:200]
        fallback["cached"] = False
        fallback["grounding"] = check_grounding(fallback, evidence)
        return fallback
