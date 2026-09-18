"""Global test isolation for the backend suite.

Two pieces of state are process-global and previously had no teardown, so a test
could leak into the next one and the suite could pass only *because* of collection
order:

* the injected model provider in ``app.services.hybrid_scorer``
  (``set_model_provider`` / ``reset_model_provider``), and
* the live-protection toggle in ``app.services.protection_service``
  (``set_protection_enabled``).

This autouse fixture resets BOTH to their defaults around every test, so ordering
can no longer hide state leakage. Per-file autouse fixtures that also reset the
provider remain valid: a second reset is idempotent and harmless.
"""
from __future__ import annotations

import os

# Authentication: give the test app a deterministic operator-local token and a
# SECURE (non-guessable) session secret, and keep it in dev (loopback) mode.
# These MUST be set before `app.main` (and thus `app.core.config`) is imported,
# because config reads the environment at module import time. This conftest is
# imported by pytest before any test module, so the values are in place for the
# whole suite. They never use the old guessable server default.
os.environ.setdefault("CHAINSHIELD_LOCAL_TOKEN", "test-operator-token-for-p5-0123456789")
os.environ.setdefault("CHAINSHIELD_DEPLOY_MODE", "dev")
os.environ.setdefault("SESSION_SECRET", "test-session-secret-for-p5-0123456789-not-guessable")
os.environ.setdefault("CHAINSHIELD_SCORE_CACHE", "off")  # never read or write the on-disk score cache
# The tests must not fetch package archives from the network: run without the package-content
# provider (package decisions then HOLD) and inject a provider explicitly where one is needed.
os.environ.setdefault("CHAINSHIELD_PACKAGE_MODEL", "off")
os.environ.setdefault("CHAINSHIELD_PACKAGE_FETCH", "off")

import pytest

from app.services import protection_service
from app.services.hybrid_scorer import reset_model_provider


@pytest.fixture(autouse=True)
def _reset_global_state():
    # Clean start: a leak from a previously-run test must not influence this one.
    reset_model_provider()
    protection_service.set_protection_enabled(True)
    yield
    # Clean finish: leave no residue for whatever runs next.
    reset_model_provider()
    protection_service.set_protection_enabled(True)
