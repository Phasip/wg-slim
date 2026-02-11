from __future__ import annotations

import logging
import os
import stat
import secrets
from contextvars import ContextVar


from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from starlette.staticfiles import StaticFiles

from config_model import SyncedConfigManager
from wg_sync_service import WgConfigSyncService
from fw_sync_service import FwRulesSyncService
from config_model import ConfigValidationError, PeerNotFoundException, PeerExistsException
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


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

token: ContextVar[str] = ContextVar("token")
request_ctx: ContextVar[Request | None] = ContextVar("request_ctx")


def revoke_active_token(app: FastAPI) -> None:
    token_value = token.get(None)
    if token_value:
        app.state.active_tokens.discard(token_value)


def create_access_token(app: FastAPI) -> str:
    token = wg_utils.generate_random_password(32)
    app.state.active_tokens.add(token)
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
  password: password
  bind_addr: "5000"
server:
  interface_name: wg0
"""


async def _get_token_bearerAuth(request: Request):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise FastAPIHTTPException(status_code=401, detail="Authentication required")

    token_in = auth.split(" ", 1)[1]
    for active_token in request.app.state.active_tokens:
        if wg_utils.secure_strcmp(token_in, active_token):
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

    log_file = _config_manager.get_log_file_path()
    logging.getLogger().addHandler(logging.FileHandler(log_file))
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

    exception_mappings: dict[type[Exception], int] = {
        ConfigValidationError: 400,
        PeerNotFoundException: 404,
        PeerExistsException: 409,
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

    async def HTTPExceptionHandler(request: Request, exc: Exception):
        assert isinstance(exc, FastAPIHTTPException)  # allow_motivation: Known type, only for type checker
        return mkerror(exc.status_code, exc.detail)

    async def _unified_exception_handler(request: Request, exc: Exception):
        for exc_type, status_code in exception_mappings.items():
            if isinstance(exc, exc_type):  # allow_motivation: ugly exception handler
                return mkerror(status_code, exc)
        return mkerror(500, "Internal server error")

    root_app.add_exception_handler(RequestValidationError, RequestValidationErrorHandler)
    root_app.add_exception_handler(FastAPIHTTPException, HTTPExceptionHandler)
    for exc in exception_mappings.keys():
        root_app.add_exception_handler(exc, _unified_exception_handler)

    root_app.state.active_tokens = set()

    root_app.state.config_manager = _config_manager
    root_app.state.sync_service = _sync_service
    root_app.state.fw_sync_service = _fw_sync_service

    root_app.dependency_overrides[_security_api.get_token_bearerAuth] = _get_token_bearerAuth

    root_app.include_router(DefaultApiRouter, prefix="/api")

    wg_openapi_impl.app_instance = root_app
    attach_ui_routes(root_app)

    logger.info("WG-Slim Ready! Config: %s", config_file)
    return root_app
