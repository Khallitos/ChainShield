"""Tests for server-side live install protection."""
from app.services.protection_service import evaluate_package, set_protection_enabled


def test_blocks_typosquat_when_enabled():
    set_protection_enabled(True)
    result = evaluate_package("training-leder", "1.0.0")
    assert result["blocked"] is True
    assert result["attack_type"] == "typosquatting"
    assert result["engine"] is not None
    assert result["engine"]["top_reasons"]
    assert result["engine"]["defense_mode"] == "hybrid"


def test_allows_when_disabled():
    set_protection_enabled(False)
    result = evaluate_package("training-leder", "1.0.0")
    assert result["blocked"] is False


def test_blocks_dependency_confusion():
    set_protection_enabled(True)
    result = evaluate_package("corp-internal-ledger-api", "9.9.9")
    assert result["blocked"] is True
    assert result["attack_type"] in ("dependency_confusion", "lab_attack")
