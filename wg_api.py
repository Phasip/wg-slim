from __future__ import annotations

import logging
import logging.handlers
import os
import stat
import secrets
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone


from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.routing import Match
from starlette.staticfiles import StaticFiles

from config_model import SyncedConfigManager
from wg_sync_service import WgConfigSyncService
from fw_sync_service import FwRulesSyncService
from config_model import ConfigValidationError, PeerNotFoundException, PeerExistsException, ConfigSyncException, DontKnowPeersPrivatekey
from pydantic_core._pydantic_core import ValidationError as PydanticCoreValidationError
from pydantic import ValidationError as PydanticValidationError
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi import HTTPException as FastAPIHTTPException
from typing import Callable, Awaitable
import wg_openapi_impl
import wg_utils
import openapi_server.security_api as _security_api
from openapi_server.apis.default_api import router as DefaultApiRouter
from openapi_server.models.error import Error as OpenAPIError

# Version info - updated during Docker build
VERSION = "dev build dev"


LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger(__name__)

token: ContextVar[str] = ContextVar("token")
request_ctx: ContextVar[Request | None] = ContextVar("request_ctx")


TOKEN_TTL = timedelta(hours=24)

HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


# Failed logins allowed per client address within the window before further
# attempts are refused with 429, whatever the password.
MAX_FAILED_LOGINS = 5
FAILED_LOGIN_WINDOW = timedelta(minutes=5)


class LoginThrottle:
    """Tracks failed logins per client address to slow down password guessing.

    Behind a reverse proxy every client shares the proxy's address unless
    uvicorn trusts its X-Forwarded-For (set FORWARDED_ALLOW_IPS).
    """

    def __init__(self) -> None:
        self._failures: dict[str, list[datetime]] = {}

    def _prune(self, now: datetime) -> None:
        cutoff = now - FAILED_LOGIN_WINDOW
        for client in list(self._failures):
            recent = [t for t in self._failures[client] if t > cutoff]
            if recent:
                self._failures[client] = recent
            else:
                del self._failures[client]

    def retry_after(self, client: str) -> int:
        """Seconds until `client` may try again, or 0 if it is not blocked."""
        now = datetime.now(timezone.utc)
        self._prune(now)
        failures = self._failures.get(client, [])
        if len(failures) < MAX_FAILED_LOGINS:
            return 0
        return max(1, int((failures[0] + FAILED_LOGIN_WINDOW - now).total_seconds()) + 1)

    def record_failure(self, client: str) -> None:
        self._failures.setdefault(client, []).append(datetime.now(timezone.utc))

    def record_success(self, client: str) -> None:
        self._failures.pop(client, None)


# The log file is rotated at this size, keeping one previous file.
LOG_MAX_BYTES = 1024 * 1024
LOG_BACKUP_COUNT = 1


class PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """A RotatingFileHandler whose files are only readable by their owner.

    The log sits next to the config and records client IPs and user agents.
    Opening with mode 0600 (rather than chmod after the fact) also covers the
    fresh file created on every rotation.
    """

    def _open(self):  # pyright: ignore[reportIncompatibleMethodOverride]
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a", encoding=self.encoding, errors=self.errors)


_installed_log_handler: logging.Handler | None = None


def install_log_handler(log_file: str) -> PrivateRotatingFileHandler:
    """Log to `log_file`, replacing the handler a previous `create_app` installed."""
    global _installed_log_handler
    root = logging.getLogger()
    if _installed_log_handler is not None:
        root.removeHandler(_installed_log_handler)
        _installed_log_handler.close()
    handler = PrivateRotatingFileHandler(log_file, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(handler)
    _installed_log_handler = handler
    return handler


def revoke_active_token(app: FastAPI) -> None:
    token_value = token.get(None)
    if token_value:
        app.state.active_tokens.pop(token_value, None)


def revoke_other_tokens(app: FastAPI) -> None:
    """Invalidate every session except the caller's.

    Used after a password change: rotating the password must cut off any token
    that leaked, otherwise a stolen 24h token outlives the credential it came
    from (and its expiry is refreshed on every request).
    """
    current = token.get(None)
    kept: dict[str, datetime] = {}
    if current:
        expiry = app.state.active_tokens.get(current)
        if expiry is not None:
            kept[current] = expiry
    revoked = len(app.state.active_tokens) - len(kept)
    app.state.active_tokens = kept
    logger.info("Revoked %d other session(s) after password change", revoked)


def prune_expired_tokens(app: FastAPI) -> None:
    """Drop expired tokens so `active_tokens` cannot grow without bound."""
    now = datetime.now(timezone.utc)
    expired = [t for t, expiry in app.state.active_tokens.items() if expiry < now]
    for t in expired:
        app.state.active_tokens.pop(t, None)


def create_access_token(app: FastAPI) -> str:
    prune_expired_tokens(app)
    token = wg_utils.generate_random_password(32)
    app.state.active_tokens[token] = datetime.now(timezone.utc) + TOKEN_TTL
    return token


def attach_ui_routes(app: FastAPI):
    """Mount static files and add UI routes onto an existing FastAPI app.

    This centralizes the UI route definitions so callers (tests or the
    `WireGuardAPI` helper) can attach the same behavior without duplicating
    code.
    """
    module_dir = os.path.dirname(os.path.abspath(__file__))
    templates = Jinja2Templates(directory=os.path.join(module_dir, "templates"))
    static_dir = os.path.join(module_dir, "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/login")
    def login_page(request: Request):  # pyright: ignore[reportUnusedFunction]
        return templates.TemplateResponse(request, "login.html", {"csp_nonce": request.state.csp_nonce, "version": VERSION})

    app.add_api_route("/", lambda: RedirectResponse(url="/login"), methods=["GET"])

    @app.get("/dashboard")
    def dashboard(request: Request):  # pyright: ignore[reportUnusedFunction]
        return templates.TemplateResponse(request, "dashboard.html", {"csp_nonce": request.state.csp_nonce, "version": VERSION})

    @app.get("/favicon.ico")
    def _favicon():  # pyright: ignore[reportUnusedFunction]
        return Response(status_code=204)


ENV_INITIAL_CONFIG = "INITIAL_CONFIG"
ENV_CONFIG_FILE = "CONFIG_FILE"

DEFAULT_CONFIG_FILE = "/data/config.yaml"

DEFAULT_INITIAL_CONFIG = """\
basic:
  bind_addr: "5000"
server:
  interface_name: wg0
"""


async def _get_token_bearerAuth(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise FastAPIHTTPException(status_code=401, detail="Authentication required")

    token_in = auth.split(" ", 1)[1]
    # Deliberately a linear scan with secure_strcmp rather than a dict lookup.
    # Hashing the presented token to index a dict leaks, through timing, how
    # much of a guess matched a real token. Do not "optimize" this to
    # `active_tokens.get(token_in)`. The table only holds live sessions, so the
    # loop is short.
    for active_token, expiry in request.app.state.active_tokens.items():
        if wg_utils.secure_strcmp(token_in, active_token) and datetime.now(timezone.utc) <= expiry:
            request.app.state.active_tokens[active_token] = datetime.now(timezone.utc) + TOKEN_TTL
            token.set(token_in)
            return token_in

    raise FastAPIHTTPException(status_code=401, detail="Invalid or inactive token")


def create_app(sync_service: WgConfigSyncService | None = None, config_file: str | None = None) -> FastAPI:
    """Create and return the configured FastAPI application."""
    if config_file is None:
        config_file = os.environ.get(ENV_CONFIG_FILE, DEFAULT_CONFIG_FILE)

    fallback_config = os.environ.get(ENV_INITIAL_CONFIG)
    if fallback_config is None or fallback_config.strip() == "":
        fallback_config = DEFAULT_INITIAL_CONFIG

    _config_manager = SyncedConfigManager.load_or_create(config_file, fallback_config)

    st = os.stat(config_file)
    if bool(st.st_mode & stat.S_IWOTH):
        logger.warning("Config file %s is world-writable; set permissions to 600 to protect secrets", config_file)

    _log_handler = install_log_handler(wg_utils.log_file_path(_config_manager.file_path))
    logger.info("Starting WG-Slim")

    _sync_service: WgConfigSyncService = sync_service if sync_service is not None else WgConfigSyncService(config_manager=_config_manager)

    _fw_sync_service: FwRulesSyncService = FwRulesSyncService(config_manager=_config_manager)

    _config_manager.add_on_config_change(_sync_service.sync_now)
    _config_manager.add_on_config_change(_fw_sync_service.sync_now)

    _sync_service.sync_now()
    _fw_sync_service.sync_now()

    root_app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)

    @root_app.middleware("http")
    async def _request_context_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]):  # pyright: ignore[reportUnusedFunction]
        """Set a ContextVar with the current Request so other code can access it outside handlers."""
        token_ctx = request_ctx.set(request)
        try:
            return await call_next(request)
        finally:
            request_ctx.reset(token_ctx)

    @root_app.middleware("http")
    async def _add_security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]):  # pyright: ignore[reportUnusedFunction]
        """Add strict security headers to every HTTP response."""
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        script_src = f"'self' 'nonce-{nonce}'"
        response.headers["Content-Security-Policy"] = f"default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; style-src 'self'; script-src {script_src}"

        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Permissions-Policy"] = (
            "accelerometer=(),autoplay=(),camera=(),display-capture=(),encrypted-media=(),"
            "fullscreen=(),geolocation=(),gyroscope=(),magnetometer=(),microphone=(),midi=(),payment=(),"
            "picture-in-picture=(),publickey-credentials-get=(),screen-wake-lock=(),sync-xhr=(),usb=(),xr-spatial-tracking=()"
        )

        proto = request.url.scheme
        if str(proto).lower() == "https":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

        return response

    # Insertion order matters: `_unified_exception_handler` returns the first
    # matching entry, so the catch-all `Exception` stays last.
    exception_mappings: dict[type[Exception], int] = {
        ConfigValidationError: 400,
        ConfigSyncException: 400,
        DontKnowPeersPrivatekey: 400,
        PeerNotFoundException: 404,
        PeerExistsException: 409,
        wg_utils.WgSectionSyntaxError: 400,
        PydanticCoreValidationError: 400,
        PydanticValidationError: 400,
        Exception: 500,
    }

    def mkerror(code: int, error: object) -> JSONResponse:
        return JSONResponse(status_code=code, content=OpenAPIError(error=str(error)).model_dump())

    async def RequestValidationErrorHandler(request: Request, exc: Exception):
        assert isinstance(exc, RequestValidationError)  # allow_motivation: Known type, only for type checker
        items: list[str] = []
        for e in exc.errors():
            fld = ".".join(str(x) for x in e["loc"][1:])
            items.append(f"{fld}: {e['msg']}")
        msg = ", ".join(items)
        return mkerror(400, msg)

    def allowed_methods(request: Request) -> str:
        # FastAPI registers one route per method, so starlette's own 405 only
        # names the methods of the first route that matched the path. Probe
        # every method through the public `matches()`, which also works for
        # FastAPI's grouped (included) routers.
        allowed = [m for m in HTTP_METHODS if any(route.matches({**request.scope, "method": m})[0] == Match.FULL for route in root_app.router.routes)]
        return ", ".join(allowed)

    async def HTTPExceptionHandler(request: Request, exc: Exception):
        # Registered for starlette's base class so routing errors (404, 405)
        # get the same Error body as the ones raised by our handlers.
        assert isinstance(exc, StarletteHTTPException)  # allow_motivation: Known type, only for type checker
        response = mkerror(exc.status_code, exc.detail)
        if exc.headers:
            response.headers.update(exc.headers)
        if exc.status_code == 405:
            response.headers["Allow"] = allowed_methods(request)
        return response

    async def _unified_exception_handler(request: Request, exc: Exception):
        for exc_type, status_code in exception_mappings.items():
            if isinstance(exc, exc_type):  # allow_motivation: ugly exception handler
                return mkerror(status_code, exc)
        return mkerror(500, "Internal server error")

    root_app.add_exception_handler(RequestValidationError, RequestValidationErrorHandler)
    root_app.add_exception_handler(StarletteHTTPException, HTTPExceptionHandler)
    for exc in exception_mappings.keys():
        root_app.add_exception_handler(exc, _unified_exception_handler)

    root_app.state.active_tokens = {}  # dict[str, datetime]: token -> expiry
    root_app.state.login_throttle = LoginThrottle()
    root_app.state.log_handler = _log_handler

    root_app.state.config_manager = _config_manager
    root_app.state.sync_service = _sync_service
    root_app.state.fw_sync_service = _fw_sync_service

    root_app.dependency_overrides[_security_api.get_token_bearerAuth] = _get_token_bearerAuth

    root_app.include_router(DefaultApiRouter, prefix="/api")

    wg_openapi_impl.app_instance = root_app
    attach_ui_routes(root_app)

    logger.info("WG-Slim Ready! Config: %s", config_file)
    return root_app
