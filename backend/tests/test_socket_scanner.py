"""Tests for Socket.dev integration (mocked HTTP)."""
from unittest.mock import MagicMock, patch

from app.schemas.scan_report import Decision, DefenseMode
from app.services.scan_service import scan_manifest_unified
from app.services.socket_scanner import scan_manifest_socket


def test_socket_fallback_when_no_token():
    findings, reasons, score, decision, meta = scan_manifest_socket(
        {"training-leder": "1.0.0"},
        "test",
    )
    assert meta["socket_configured"] is False
    assert meta["engine"] == "socket_fallback_baseline"
    assert decision in (Decision.BLOCK, Decision.WARN, Decision.ALLOW)


@patch("app.services.socket_client.is_configured", return_value=True)
@patch("app.services.socket_client.scan_dependencies")
def test_socket_manifest_scan_with_alerts(mock_scan, _configured):
    mock_scan.return_value = (
        True,
        [
            {
                "purl": "pkg:npm/training-leder@1.0.0",
                "alerts": [
                    {
                        "type": "didYouMean",
                        "severity": "high",
                        "props": {"description": "Similar to training-ledger"},
                    }
                ],
                "score": {"depscore": 0.2},
            }
        ],
        None,
    )
    findings, reasons, score, decision, meta = scan_manifest_socket(
        {"training-leder": "1.0.0"},
        "demo",
    )
    assert meta["engine"] == "socket_dev_api"
    assert len(findings) >= 1
    assert score >= 0.75
    assert decision == Decision.BLOCK
    assert any("Socket" in r.description for r in reasons)


@patch("app.services.socket_client.is_configured", return_value=True)
@patch("app.services.socket_client.scan_dependencies")
def test_scan_manifest_unified_socket_mode(mock_scan, _configured):
    mock_scan.return_value = (
        True,
        [
            {
                "purl": "pkg:npm/training-leder@1.0.0",
                "alerts": [{"type": "didYouMean", "severity": "high", "props": {}}],
            }
        ],
        None,
    )
    report = scan_manifest_unified(
        {"training-leder": "1.0.0"},
        "demo-site",
        DefenseMode.SOCKET,
    )
    assert report.defense_mode == DefenseMode.SOCKET
    assert report.metadata["engine"] == "socket_dev_api"
    assert report.summary.findings_count >= 1
