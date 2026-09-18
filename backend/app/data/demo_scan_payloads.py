"""Lab demo payloads when a repo has no scannable artifacts."""
from __future__ import annotations

from typing import Any, Dict

DEMO_ATTACK_DEPS: Dict[str, str] = {
    "training-leder": "1.0.0",
    "react": "18.3.1",
    "corp-internal-ledger-api": "9.9.9",
}

DEMO_SBOM: Dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "training-leder",
            "version": "1.0.0",
            "purl": "pkg:npm/training-leder@1.0.0",
        },
        {
            "type": "library",
            "name": "react",
            "version": "18.3.1",
            "purl": "pkg:npm/react@18.3.1",
        },
        {
            "type": "library",
            "name": "corp-internal-ledger-api",
            "version": "9.9.9",
            "purl": "pkg:npm/corp-internal-ledger-api@9.9.9",
        },
    ],
}

DEMO_WORKFLOW: Dict[str, Any] = {
    "name": "CI",
    "on": {"pull_request_target": {}},
    "jobs": {
        "build": {
            "steps": [
                {"uses": "actions/checkout@v4"},
                {"run": "echo ${{ github.event.issue.title }}"},
            ],
        },
    },
}
