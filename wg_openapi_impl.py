"""Implementation adapter for the generated OpenAPI FastAPI project.

This module provides a minimal subclass of the generated
`BaseDefaultApi` so that the generated router delegates to our code.
Importing this module at startup will register the implementation via
`BaseDefaultApi.__init_subclass__`.
"""

from openapi_server.apis.default_api_base import BaseDefaultApi

import os
import logging


import wg_manager
import config_model
import wg_api

from fastapi import HTTPException, Response, FastAPI
from fastapi.responses import JSONResponse

import wg_utils

from openapi_server.models.success import Success
from openapi_server.models.yaml_response import YamlResponse
from openapi_server.models.server_status import ServerStatus
from openapi_server.models.server import Server
from openapi_server.models.server_logs_response import ServerLogsResponse
from openapi_server.models.peers_list import PeersList
from openapi_server.models.config_response import ConfigResponse
from openapi_server.models.peer import Peer
from openapi_server.models.login_post200_response import LoginPost200Response
from openapi_server.models.login_request import LoginRequest
from openapi_server.models.config_put_request import ConfigPutRequest
from openapi_server.models.server_yaml_put_request import ServerYamlPutRequest
from openapi_server.models.peers_post_request import PeersPostRequest
from openapi_server.models.peers_peer_name_yaml_put_request import PeersPeerNameYamlPutRequest
from openapi_server.models.settings_password_put_request import SettingsPasswordPutRequest
from openapi_server.models.config_import_wg_post_request import ConfigImportWgPostRequest
from openapi_server.models.update_all_peers_post_request import UpdateAllPeersPostRequest

logger = logging.getLogger(__name__)

# Number of trailing log lines returned by `GET /server/logs`.
LOG_TAIL_LINES = 1000

app_instance: FastAPI | None = None


def _get_app() -> FastAPI:
    assert app_instance is not None, "app_instance is not set"
    return app_instance


def get_cm() -> config_model.SyncedConfigManager:
    return _get_app().state.config_manager


class DefaultApiImpl(BaseDefaultApi):
    """API implementation that delegates to the project's services.

    Exception handling is intentionally narrow: ImportErrors are not
    swallowed, and only expected runtime errors are converted into
    HTTPException responses so unexpected failures surface during
    development or CI. Domain exceptions (`ConfigSyncException`,
    `DontKnowPeersPrivatekey`, `PeerNotFoundException`, ...) are mapped to
    status codes centrally in `wg_api.create_app`, so handlers let them
    propagate instead of translating each one.
    """

    async def login_post(self, login_request: LoginRequest | None) -> LoginPost200Response:
        if login_request is None:
            raise HTTPException(status_code=400, detail="Missing login request body")

        password = login_request.password

        cfg = get_cm()
        expected = cfg.config.basic.password

        req = wg_api.request_ctx.get()
        assert req is not None, "request context is not set"
        assert req.client is not None, "request client is not set"

        host = req.client.host
        port = req.client.port
        remote = f"{host}:{port}"
        ua = req.headers.get("user-agent", None)

        if not wg_utils.secure_strcmp(password, expected):
            logger.warning("Login failed from %s user_agent=%s", remote, ua)
            raise HTTPException(status_code=403, detail="Invalid password")

        logger.info("Login succeeded from %s user_agent=%s", remote, ua)

        token = wg_api.create_access_token(app=_get_app())
        return LoginPost200Response(access_token=token, token_type="bearer")

    async def logout_get(self) -> Success:
        wg_api.revoke_active_token(app=_get_app())
        return Success(message="logged out")

    async def server_yaml_get(self) -> YamlResponse:
        cfg = get_cm()
        server_peer = config_model.get_peer(cfg.config, cfg.config.server.name)
        return YamlResponse(yaml=config_model.ConfigHelper.to_yaml(server_peer))

    async def server_yaml_put(self, server_yaml_put_request: ServerYamlPutRequest | None) -> None:
        if server_yaml_put_request is None:
            raise HTTPException(status_code=400, detail="Missing server yaml body")

        cfg = get_cm()
        server_peer = config_model.get_peer(cfg.config, cfg.config.server.name)
        config_model.ConfigHelper.update_from_yaml(server_peer, server_yaml_put_request.yaml)
        cfg.save()
        return None

    async def server_status_get(self) -> ServerStatus:
        cfg = get_cm()
        interface = cfg.config.server.interface_name
        is_running = wg_manager.WgManager.is_interface_up(interface)

        if not is_running:
            return ServerStatus(status="down", interface=interface, is_running=False)

        return ServerStatus(status="up", interface=interface, is_running=True)

    async def server_get(self) -> Server:
        s = get_cm().config.server
        return Server(name=s.name, interface_name=s.interface_name)

    async def server_logs_get(self) -> ServerLogsResponse:
        log_file = wg_utils.log_file_path(get_cm().file_path)
        if not os.path.exists(log_file):
            return ServerLogsResponse(logs=[])
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return ServerLogsResponse(logs=[line.rstrip("\n") for line in lines[-LOG_TAIL_LINES:]])

    async def server_logs_delete(self) -> Success:
        handler = _get_app().state.log_handler
        handler.acquire()
        try:
            handler.stream.seek(0)
            handler.stream.truncate(0)
        finally:
            handler.release()
        return Success(message="")

    async def wg_show_get(self) -> dict[str, str] | None:
        cfg = get_cm().config
        blocks = wg_manager.WgManager.get_wg_show_peer_blocks(cfg.server.interface_name)
        result: dict[str, str] = {}

        for p in cfg.peers:
            # A peer edited through the API may lack a PublicKey; that must not
            # break `wg show` for every other peer.
            pub = wg_utils.parse_wg_section(p.as_peer).get("PublicKey")
            if pub and pub in blocks:
                result[p.name] = blocks[pub]
            elif p.name == cfg.server.name:
                result[p.name] = "[Peer is active server]"
            else:
                result[p.name] = "[Peer inactive in WireGuard]"

        return result

    async def peers_get(self) -> PeersList:
        peers = [Peer.model_validate(p.model_dump()) for p in get_cm().config.peers]
        return PeersList(peers=peers)

    async def peers_post(self, peers_post_request: PeersPostRequest | None) -> JSONResponse | None:
        if peers_post_request is None:
            raise HTTPException(status_code=400, detail="Missing peers post body")
        name = peers_post_request.name
        if not name:
            raise HTTPException(status_code=400, detail="Missing peer name")

        peer = get_cm().add_peer(name)
        return JSONResponse(status_code=201, content=peer.model_dump())

    async def peers_peer_name_delete(self, peer_name: str) -> None:
        get_cm().remove_peer(peer_name)
        return None

    async def peers_peer_name_config_get(self, peer_name: str) -> ConfigResponse:
        return ConfigResponse(config=get_cm().get_peer_config_string(peer_name))

    async def peers_peer_name_qr_get(self, peer_name: str) -> Response:
        png = wg_utils.render_qrcode_png(get_cm().get_peer_config_string(peer_name))
        return Response(content=png, media_type="image/png")

    async def peers_peer_name_regenerate_key_post(self, peer_name: str) -> Success:
        get_cm().regenerate_key(peer_name)
        return Success(message="")

    async def peers_peer_name_enable_post(self, peer_name: str) -> None:
        self._set_peer_enabled(peer_name, True)
        return None

    async def peers_peer_name_disable_post(self, peer_name: str) -> None:
        self._set_peer_enabled(peer_name, False)
        return None

    @staticmethod
    def _set_peer_enabled(peer_name: str, enabled: bool) -> None:
        cfg = get_cm()
        config_model.get_peer(cfg.config, peer_name).enabled = enabled
        cfg.save()

    async def config_get(self) -> ConfigResponse:
        raw = get_cm().get_raw_config(censor_password=True)
        return ConfigResponse(config=raw)

    async def config_put(self, config_put_request: ConfigPutRequest | None) -> Success:
        if config_put_request is None:
            raise HTTPException(status_code=400, detail="Missing config put body")
        get_cm().set_raw_config(config_put_request.yaml, ignore_password=True)
        return Success(message="")

    async def config_import_wg_post(self, config_import_wg_post_request: ConfigImportWgPostRequest | None) -> Success:
        if config_import_wg_post_request is None:
            raise HTTPException(status_code=400, detail="Missing import wg body")
        wg_conf = config_import_wg_post_request.wg_config
        endpoint = config_import_wg_post_request.endpoint
        cm = get_cm()
        if len(cm.config.peers) != 1:
            raise HTTPException(status_code=400, detail="Importing WireGuard configs is only supported when no peers exist except the server peer")

        parsed = config_model.parse_wg_conf(wg_conf, endpoint)
        cm.config.server = Server.model_validate(parsed["server"])
        cm.config.peers = [Peer.model_validate(p) for p in parsed["peers"]]
        cm.save()

        return Success(message="")

    async def settings_password_put(self, settings_password_put_request: SettingsPasswordPutRequest | None) -> Success:
        if settings_password_put_request is None:
            raise HTTPException(status_code=400, detail="Missing body")
        current = settings_password_put_request.current_password
        new_pw = settings_password_put_request.new_password
        confirm = settings_password_put_request.confirm_password

        if not wg_utils.secure_strcmp(new_pw, confirm):
            raise HTTPException(status_code=400, detail="New password and confirm password do not match")

        cfg = get_cm()

        if not wg_utils.secure_strcmp(current, cfg.config.basic.password):
            raise HTTPException(status_code=403, detail="Invalid password")

        cfg.config.basic.password = new_pw
        cfg.save()

        # The old password is gone; any session created with it must go too.
        # The caller keeps its own token - it just proved it knows the password.
        wg_api.revoke_other_tokens(app=_get_app())

        return Success(message="")

    async def peers_peer_name_yaml_get(self, peer_name: str) -> YamlResponse:
        peer = config_model.get_peer(get_cm().config, peer_name)
        return YamlResponse(yaml=config_model.ConfigHelper.to_yaml(peer))

    async def peers_peer_name_yaml_put(self, peer_name: str, peers_peer_name_yaml_put_request: PeersPeerNameYamlPutRequest | None) -> None:
        if peers_peer_name_yaml_put_request is None:
            raise HTTPException(status_code=400, detail="Missing peers yaml body")
        get_cm().update_peer_from_yaml(peer_name, peers_peer_name_yaml_put_request.yaml)
        return None

    async def update_all_peers_post(self, update_all_peers_post_request: UpdateAllPeersPostRequest) -> None:
        if update_all_peers_post_request is None:
            raise HTTPException(status_code=400, detail="Missing body")
        get_cm().apply_template_to_peers(update_all_peers_post_request.template_peer)
        return None

    async def health_get(self) -> dict[str, str]:
        return {"status": "healthy"}
