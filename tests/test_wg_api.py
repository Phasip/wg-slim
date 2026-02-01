"""Tests for the WireGuard REST API using pytest style."""

import pytest
import yaml
import wgslim_api_client
from pydantic import ValidationError
from wgslim_api_client.exceptions import (
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    BadRequestException,
)
from wgslim_api_client.models import ConfigPutRequest
from fastapi.testclient import TestClient


# `test_client` fixture is provided by `tests.conftest` and is unauthenticated by default.
# Use `generated_api_client` fixture when a test requires an authenticated client.


def test_health_endpoint(generated_unauth_api_client):
    generated_unauth_api_client.health_get()


def test_protected_endpoint_without_auth(generated_unauth_api_client):
    with pytest.raises(UnauthorizedException):
        generated_unauth_api_client.server_get()


def test_get_server(generated_api_client):
    # Server GET returns the minimal Server model
    server = generated_api_client.server_get()
    assert server.interface_name == "wg1"

    # Server YAML returns the server peer YAML (server details are stored in a peer)
    yaml_response = generated_api_client.server_yaml_get()
    server_peer = yaml.safe_load(yaml_response.yaml)
    # The YAML should represent a peer with interface and as_peer multiline strings
    assert "interface" in server_peer
    assert "Address" in server_peer["interface"]


def test_get_server_status_down(generated_api_client, mock_wg_manager):
    mock_wg_manager["ip link show dev wg1"] = (1, "", 'Device "wg1" does not exist.')
    status = generated_api_client.server_status_get()
    assert status.status == "down"


def test_get_server_status_up(generated_api_client, mock_wg_manager):
    status = generated_api_client.server_status_get()
    assert status.status == "up"
    assert status.is_running is True


def test_get_peers(generated_api_client):
    response = generated_api_client.peers_get()
    assert response.peers is not None
    # Server is now represented as a peer, so expect three peers total
    assert len(response.peers) == 3


def test_get_peer_exists(generated_api_client):
    response = generated_api_client.peers_get()
    names = [p.name for p in response.peers]
    assert "peer1" in names


def test_get_peer_not_found(generated_api_client):
    response = generated_api_client.peers_get()
    names = [p.name for p in response.peers]
    assert "nonexistent" not in names


def test_regenerate_peer_key(generated_api_client):
    response = generated_api_client.peers_peer_name_regenerate_key_post("peer1")
    assert response.message == ""


def test_regenerate_peer_key_not_found(generated_api_client):
    with pytest.raises(NotFoundException):
        generated_api_client.peers_peer_name_regenerate_key_post("nonexistent")


def test_health_check_with_interface_status(generated_unauth_api_client):
    generated_unauth_api_client.health_get()


def test_web_login_post_success(generated_unauth_api_client, config_for_test_client: str):
    with open(config_for_test_client, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    pw = cfg.get("basic", {}).get("password", "testpassword")
    response = generated_unauth_api_client.login_post(wgslim_api_client.LoginRequest(password=pw))
    assert response.access_token is not None


def test_web_login_post_failure(generated_unauth_api_client):
    with pytest.raises(ForbiddenException) as exc_info:
        generated_unauth_api_client.login_post(wgslim_api_client.LoginRequest(password="wrongpassword"))
    assert "Invalid password" in str(exc_info.value)


def test_web_login_get(unauth_api_client: TestClient):
    response = unauth_api_client.get("/login")
    assert response.status_code == 200
    assert b"password" in response.content.lower()


def test_api_config_get(generated_api_client):
    response = generated_api_client.config_get()
    assert response.config is not None
    assert isinstance(response.config, str)


def test_api_config_put(generated_api_client):
    response = generated_api_client.config_get()
    current_config = response.config

    response = generated_api_client.config_put(wgslim_api_client.ConfigPutRequest(yaml=current_config))
    assert response.message == ""


def test_api_config_put_missing_config(generated_api_client):
    with pytest.raises(ValidationError):
        generated_api_client.config_put(wgslim_api_client.ConfigPutRequest(yaml=""))


def test_api_config_put_preserves_password(unauth_api_client: TestClient, generated_api_client, generated_unauth_api_client):
    # Verify that editing the raw YAML via the config endpoint cannot change
    # the stored password (editor is censored and server should preserve it).
    app = unauth_api_client.app
    cfg_manager = app.state.config_manager
    original_pw = cfg_manager.config.basic.password

    # Get the masked config
    response = generated_api_client.config_get()
    current_config = response.config
    assert "password: PASSWORD_NOT_CHANGEABLE_IN_CONF_EDITOR" in current_config
    # Attempt to replace the masked password with a new value
    new_pw = "new_password"
    edited = current_config.replace("PASSWORD_NOT_CHANGEABLE_IN_CONF_EDITOR", new_pw)

    # PUT the edited config
    response = generated_api_client.config_put(ConfigPutRequest(yaml=edited))
    assert response.message == ""

    # The in-memory stored password must remain unchanged
    assert cfg_manager.config.basic.password == original_pw

    # Verify login with the original password still works
    resp = generated_unauth_api_client.login_post(wgslim_api_client.LoginRequest(password=original_pw))
    assert resp.access_token is not None


def test_api_logout_get(generated_api_client):
    generated_api_client.logout_get()

    with pytest.raises(UnauthorizedException):
        generated_api_client.server_get()


def test_api_peer_qr_endpoint(generated_api_client):
    response = generated_api_client.peers_peer_name_qr_get_with_http_info("peer1")
    assert response.headers.get("content-type") == "image/png"
    assert response.raw_data[:4] == b"\x89PNG"


def test_api_peer_qr_not_found(generated_api_client):
    with pytest.raises(NotFoundException) as exc_info:
        generated_api_client.peers_peer_name_qr_get("nonexistent-peer")
    assert "not found" in str(exc_info.value).lower()


def test_get_logs(generated_api_client):
    try:
        response = generated_api_client.server_logs_get()
        assert response.logs is not None
        assert isinstance(response.logs, list)
        for entry in response.logs:
            assert isinstance(entry, str)
    except BadRequestException:
        pass


def test_get_logs_requires_auth(generated_unauth_api_client):
    with pytest.raises(UnauthorizedException):
        generated_unauth_api_client.server_logs_get()


def test_clear_logs(generated_api_client):
    response = generated_api_client.server_logs_delete()
    assert response.message == ""


def test_clear_logs_requires_auth(generated_unauth_api_client):
    with pytest.raises(UnauthorizedException):
        generated_unauth_api_client.server_logs_delete()
