"""Tests for composite scan API."""
from fastapi.testclient import TestClient

from app.data.demo_scan_payloads import DEMO_ATTACK_DEPS, DEMO_SBOM, DEMO_WORKFLOW
from app.main import app

client = TestClient(app)


def test_scan_run_composite():
    resp = client.post(
        "/v1/scan/run",
        json={
            "source": "demo-site",
            "defense_mode": "hybrid",
            "dependencies": DEMO_ATTACK_DEPS,
            "sbom": DEMO_SBOM,
            "workflow": DEMO_WORKFLOW,
            "compare_defense_modes": False,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"].startswith("scn_cmp_")
    assert data["summary"]["findings_count"] >= 1
    assert len(data["pipeline"]) == 3
    assert data["manifest"]["scan_type"] == "manifest"
    assert data["sbom"]["scan_type"] == "sbom"
    assert data["workflow"]["scan_type"] == "workflow"
    assert len(data["findings"]) >= 1
    assert all("scan_layer" in f for f in data["findings"])
    assert len(data["defense_comparison"]) == 0

    cached = client.get(f"/v1/scan/composite/{data['scan_id']}")
    assert cached.status_code == 200
    assert cached.json()["scan_id"] == data["scan_id"]


def test_scan_run_unblocked_allows():
    resp = client.post(
        "/v1/scan/run",
        json={
            "source": "demo-site",
            "defense_mode": "unblocked",
            "dependencies": DEMO_ATTACK_DEPS,
            "sbom": DEMO_SBOM,
            "workflow": DEMO_WORKFLOW,
            "compare_defense_modes": False,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["manifest"]["summary"]["decision"] == "allow"
