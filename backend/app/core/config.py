"""Runtime configuration."""
import os
import secrets
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
except ImportError:
    pass

APP_TITLE = "Supply Chain Security Platform"
APP_VERSION = "0.1.0"
API_PREFIX = "/v1"

# Deployment mode: "dev" (loopback baseline; per-process ephemeral secrets) or
# "production" (secure defaults enforced, fail-fast on misconfiguration). See
# `assert_secure_deploy()` below.
DEPLOY_MODE = os.getenv("CHAINSHIELD_DEPLOY_MODE", "dev").strip().lower()

# Socket.dev: https://docs.socket.dev/docs/socket-cli
SOCKET_API_BASE_URL = os.getenv("SOCKET_API_BASE_URL", "https://api.socket.dev/v0").rstrip("/")
SOCKET_SECURITY_API_TOKEN = (
    os.getenv("SOCKET_SECURITY_API_TOKEN") or os.getenv("SOCKET_API_TOKEN") or ""
).strip()

# GitHub: https://docs.github.com/en/rest
GITHUB_API_BASE_URL = os.getenv("GITHUB_API_BASE_URL", "https://api.github.com").rstrip("/")
GITHUB_TOKEN = (os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT") or "").strip()
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "").strip()
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "").strip()
GITHUB_OAUTH_REDIRECT_URI = os.getenv(
    "GITHUB_OAUTH_REDIRECT_URI",
    "http://127.0.0.1:8000/v1/github/callback",
).strip()
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
GITHUB_OAUTH_ENABLED = bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)

# ---------------------------------------------------------------------------
# Session secret: no guessable default. In dev mode a non-guessable,
# per-process secret is generated; in production the operator must provide
# SESSION_SECRET explicitly (fail-fast enforced by `assert_secure_deploy`).
# ---------------------------------------------------------------------------
_GUESSABLE_SESSION_SECRET = "supply-chain-lab-dev-secret-change-me"


def _load_session_secret() -> str:
    env = (os.getenv("SESSION_SECRET") or "").strip()
    if env and env != _GUESSABLE_SESSION_SECRET:
        return env
    if DEPLOY_MODE == "dev":
        # Non-guessable dev secret: never the old fixed default. It is kept in a local,
        # git-ignored file so a backend restart does not silently drop the browser's GitHub
        # session (every repository scan would otherwise fail with "GitHub not connected").
        fpath = Path(__file__).resolve().parents[2] / ".chainshield-session-secret"
        try:
            stored = fpath.read_text(encoding="utf-8").strip()
            if len(stored) >= 32:
                return stored
        except OSError:
            pass
        fresh = secrets.token_urlsafe(48)
        try:
            fpath.write_text(fresh, encoding="utf-8")
        except OSError:
            pass
        return fresh
    return ""


SESSION_SECRET = _load_session_secret()

# Allowed origins for CORS, Origin/CSRF checks and the WebSocket install-alert
# hub (loopback/localhost baseline + configured frontend). Kept as an explicit
# allowlist.
ALLOWED_ORIGINS = [
    FRONTEND_URL.rstrip("/"),
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]

# Local trusted-client capability: a per-operator, non-shared token held
# server-side. Source order: env `CHAINSHIELD_LOCAL_TOKEN` → file
# `CHAINSHIELD_LOCAL_TOKEN_FILE` (default `backend/.chainshield-local-token`).
# In dev mode, if neither is set, an ephemeral non-guessable token is generated
# so the loopback CLI gate keeps working without a shared default; in production
# the operator MUST configure one (enforced by `assert_secure_deploy`).
_DEFAULT_TOKEN_FILE = Path(__file__).resolve().parents[2] / ".chainshield-local-token"


def _resolve_local_token() -> str:
    env = (os.getenv("CHAINSHIELD_LOCAL_TOKEN") or "").strip()
    if env:
        return env
    fpath = os.getenv("CHAINSHIELD_LOCAL_TOKEN_FILE") or str(_DEFAULT_TOKEN_FILE)
    try:
        if Path(fpath).is_file():
            value = Path(fpath).read_text(encoding="utf-8").strip()
            if value:
                return value
    except OSError:
        pass
    if DEPLOY_MODE == "dev":
        return secrets.token_urlsafe(32)
    return ""


LOCAL_TOKEN = _resolve_local_token()

# Durable JSONL audit log path. Disabled by default in dev (keeps the loopback
# dev suite hermetic); enabled in production. Override with CHAINSHIELD_AUDIT_LOG.
if DEPLOY_MODE == "production":
    _default_audit_log = str(Path(__file__).resolve().parents[2] / "data" / "audit.log")
else:
    _default_audit_log = ""
AUDIT_LOG_PATH = os.getenv("CHAINSHIELD_AUDIT_LOG", "") or _default_audit_log


def assert_secure_deploy(
    mode: str = "production",
    session_secret: str = SESSION_SECRET,
    local_token: str = LOCAL_TOKEN,
    guessable_secret: str = _GUESSABLE_SESSION_SECRET,
) -> None:
    """Fail fast at startup in non-local modes instead of silently downgrading.

    Production requires an explicitly set, non-guessable SESSION_SECRET and a
    configured operator/local token. Dev (loopback baseline) is exempt so local
    development keeps working.
    """
    if mode != "production":
        return
    if not session_secret:
        raise RuntimeError(
            "SESSION_SECRET must be set to a strong value in production mode "
            "(there is NO guessable default)."
        )
    if session_secret == guessable_secret:
        raise RuntimeError(
            "SESSION_SECRET uses the known guessable default; replace it with a strong value."
        )
    if not local_token:
        raise RuntimeError(
            "CHAINSHIELD_LOCAL_TOKEN (or a .chainshield-local-token file) must be "
            "configured in production so the CLI/gate can authenticate."
        )


# Google Gemini: grounded block reports (interpreter only)
GEMINI_API_KEY = (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or "").strip()
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite").strip()
GEMINI_API_BASE = os.getenv(
    "GEMINI_API_BASE", "https://generativelanguage.googleapis.com/v1beta"
).rstrip("/")