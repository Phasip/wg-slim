"""Entry point that starts uvicorn using bind_addr from the config."""

# ruff: noqa: E402
import os
import warnings

# Match pytest `filterwarnings` entries from pyproject.toml
warnings.filterwarnings(
    "ignore",
    message=r"`regex` has been deprecated, please use `pattern` instead",
    category=Warning,
    module=r".*openapi_server.*",
)
warnings.filterwarnings(
    "ignore",
    message=r"websockets.server.WebSocketServerProtocol is deprecated",
    category=DeprecationWarning,
    module=r"uvicorn.*",
)
warnings.filterwarnings(
    "ignore",
    message=r"websockets.legacy is deprecated; see.*",
    category=DeprecationWarning,
    module=r"websockets.*",
)

import uvicorn

from wg_api import ENV_CONFIG_FILE, DEFAULT_CONFIG_FILE, ENV_INITIAL_CONFIG, DEFAULT_INITIAL_CONFIG
from config_model import SyncedConfigManager

# Lives in wg_utils so the container healthcheck can reuse it without importing
# the whole application.
from wg_utils import parse_bind_addr


def main() -> None:
    config_file = os.environ.get(ENV_CONFIG_FILE, DEFAULT_CONFIG_FILE)

    fallback_config = os.environ.get(ENV_INITIAL_CONFIG)
    if fallback_config is None or fallback_config.strip() == "":
        fallback_config = DEFAULT_INITIAL_CONFIG

    config_manager = SyncedConfigManager.load_or_create(config_file, fallback_config)
    bind_addr = str(config_manager.config.basic.bind_addr)

    host, port = parse_bind_addr(bind_addr)

    uvicorn.run(
        "wg_api:create_app",
        factory=True,
        host=host,
        port=port,
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
