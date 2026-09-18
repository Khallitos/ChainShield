"""FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import (
    ALLOWED_ORIGINS,
    API_PREFIX,
    APP_TITLE,
    APP_VERSION,
    DEPLOY_MODE,
    SESSION_SECRET,
    assert_secure_deploy,
)
from app.api.routes_health import router as health_router
from app.api.routes_attacks import router as attacks_router
from app.api.routes_lab import router as lab_router
from app.api.routes_scan import router as scan_router
from app.api.routes_trust import router as trust_router
from app.api.routes_ml import router as ml_router
from app.api.routes_socket import router as socket_router
from app.api.routes_github import router as github_router
from app.api.routes_settings import router as settings_router
from app.api.routes_reports import router as reports_router
from app.api.routes_scheduled_scan import router as scheduled_scan_router
from app.api.routes_overview import router as overview_router
from app.policy.decision_contract import ModelStatus
from app.services.schedule_scan_service import start_scheduler, stop_scheduler

# Fail fast on a non-local deploy that lacks secure session/token config.
# In dev (loopback) mode this is a no-op so local development keeps working.
assert_secure_deploy()


@asynccontextmanager
async def lifespan(app: FastAPI):
    _install_package_model()
    start_scheduler()
    yield
    stop_scheduler()


def _install_package_model() -> None:
    """Use the package-content model for package layers unless it is switched off.

    Set ``CHAINSHIELD_PACKAGE_MODEL=off`` to run without it; package decisions then hold
    instead of allowing (the default policy requires a model).
    """
    import os

    if os.getenv("CHAINSHIELD_PACKAGE_MODEL", "on").lower() in ("off", "0", "false"):
        return
    from app.services.hybrid_scorer import PackageContentModelProvider, set_model_provider

    provider = PackageContentModelProvider()
    if provider.status() is ModelStatus.LOADED:
        set_model_provider(provider)


app = FastAPI(title=APP_TITLE, version=APP_VERSION, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Loopback-first session defaults. In production (non-dev) the cookie is
# HTTPS-only; in dev we keep https_only=False to match the loopback baseline.
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    same_site="lax",
    https_only=(DEPLOY_MODE != "dev"),
)

app.include_router(health_router, prefix=API_PREFIX)
app.include_router(attacks_router, prefix=API_PREFIX)
app.include_router(lab_router, prefix=API_PREFIX)
app.include_router(scan_router, prefix=API_PREFIX)
app.include_router(trust_router, prefix=API_PREFIX)
app.include_router(ml_router, prefix=API_PREFIX)
app.include_router(socket_router, prefix=API_PREFIX)
app.include_router(github_router, prefix=API_PREFIX)
app.include_router(settings_router, prefix=API_PREFIX)
app.include_router(reports_router, prefix=API_PREFIX)
app.include_router(scheduled_scan_router, prefix=API_PREFIX)
app.include_router(overview_router, prefix=API_PREFIX)
