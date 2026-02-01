"""Shared pytest fixtures for unit tests.

This file centralizes fixtures previously defined inside individual test modules.
"""

import os
import pytest
import yaml
from fastapi.testclient import TestClient
import wg_api
from unittest.mock import patch as _patch
import requests
import json


class _MockSyncService:
    def get_sync_status(self):
        return {"running": False, "sync_count": 0, "last_error": None, "last_error_time": None}

    def sync_now(self):
        return None


@pytest.fixture
def mock_sync_service():
    """Return a mock sync service instance for tests."""
    return _MockSyncService()


@pytest.fixture
def unauth_api_client(config_for_test_client, mock_sync_service):
    """Return an unauthenticated TestClient using CONFIG_FILE."""
    os.environ["CONFIG_FILE"] = config_for_test_client

    app = wg_api.create_app(sync_service=mock_sync_service)
    client = TestClient(app)
    yield client


@pytest.fixture
def generated_unauth_api_client(unauth_api_client):
    """Return a generated wgslim_api_client.DefaultApi wrapping TestClient."""
    import wgslim_api_client

    base = str(unauth_api_client.base_url).rstrip("/")
    configuration = wgslim_api_client.Configuration(host=f"{base}/api")
    api_client = wgslim_api_client.ApiClient(configuration)

    def _request(method, url, headers=None, body=None, post_params=None, _request_timeout=None):
        kwargs = {"headers": headers}

        if body is not None:
            content_type = (headers or {}).get("Content-Type", "")
            if "json" in content_type.lower():
                if isinstance(body, str):
                    kwargs["json"] = json.loads(body)
                else:
                    kwargs["json"] = body
            else:
                kwargs["data"] = body
        elif post_params:
            kwargs["data"] = post_params

        response = unauth_api_client.request(method, url, **kwargs)

        class _Wrapper:
            status = response.status_code
            reason = None
            data = response.content

            def read(self):
                return self.data

            def getheaders(self):
                return dict(response.headers)

            def getheader(self, name, default=None):
                return response.headers.get(name, default)

        return _Wrapper()

    api_client.rest_client.request = _request
    return wgslim_api_client.DefaultApi(api_client)


@pytest.fixture
def generated_api_client(generated_unauth_api_client):
    """Return authenticated generated wgslim_api_client.DefaultApi."""
    import wgslim_api_client

    response = generated_unauth_api_client.login_post(wgslim_api_client.LoginRequest(password="testpassword"))
    generated_unauth_api_client.api_client.configuration.access_token = response.access_token
    return generated_unauth_api_client


@pytest.fixture
def mock_wg_manager():
    """Patch only `WgManager._run_command` to return fixed outputs from a dict.

    The fixture yields the `outputs` dict so tests can modify or extend it.
    Each mapping should use the command string as the key and return a tuple
    `(return_code, stdout, stderr)`.

    A few example entries are provided; the test author can replace or add
    commands as needed.
    """
    outputs = {
        "wg show": (0, "interface: wg1\npeer: peer1", ""),
        "wg set": (0, "", ""),
        "wg show wg1 dump": (
            0,
            """oDc9eSDHLHnCHoJLSAJoP5t0oVggdS4v/88nyJDMDlw=	9eTs8Qu4TTtpfgw2giifjHYNLLiJeAONb5H7KfCofgA=	46396	off
                WTz4e3nWf77WBypawV7BixKwaqNRW6n4H2ZPu5iRoRI=	p75rBOsUAKmQER31HnExVGRMTS2s4xDgVrnaJUnUX2A=	198.51.100.1:51820	10.0.0.0/24	1767101844	88658272	876116492	60""",
            "",
        ),
        "ip link show dev wg1": (
            0,
            "5: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/none ",
            "",
        ),
    }

    def _fake_run_command(cmd, *args, **kwargs):
        key = " ".join(cmd)
        if key in outputs:
            return outputs[key]
        raise RuntimeError(f"Unexpected command: {key}")

    patcher = _patch("wg_manager.WgManager._run_command", new=_fake_run_command)
    patcher.start()
    try:
        yield outputs
    finally:
        patcher.stop()


@pytest.fixture
def config_for_test_client(tmp_path):
    """Return a dedicated config file path for `test_client` to use.

    The config YAML is written to `tmp_path/config.yaml` and the path is returned.
    """
    # New config layout: server is minimal (name + interface_name)
    # and the server's interface/as_peer are stored in a peer with the same name.
    server_peer = {
        "name": "server",
        "interface": "Address = 10.0.0.1/24\nListenPort = 51820\nPrivateKey = KEY",
        "as_peer": "PublicKey = PUB\nEndpoint = test:51820",
        "enabled": True,
        "default": True,
    }

    base = {
        "basic": {"password": "testpassword", "bind_addr": "5000"},
        "server": {"name": "server", "interface_name": "wg1"},
        "peers": [
            server_peer,
            {
                "name": "peer1",
                "interface": "Address = 10.0.0.2/32\nPrivateKey = peer1_private_key\nDNS = 8.8.8.8\n",
                "as_peer": "PublicKey = peer1_public_key\nAllowedIPs = 10.0.0.2/32\n",
            },
            {
                "name": "peer2",
                "interface": "Address = 10.0.0.3/32\nPrivateKey = peer2_private_key\nDNS = 8.8.8.8\n",
                "as_peer": "PublicKey = peer2_public_key\nAllowedIPs = 10.0.0.3/32\n",
            },
        ],
    }

    config_path = tmp_path / "config.yaml"
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(base, f)

    return str(config_path)


@pytest.fixture
def base_url(wg_slim_container):
    raise ValueError("The `base_url` fixture has been renamed to `container_simple`. Please update your tests accordingly.")


@pytest.fixture
def container_simple(wg_slim_container):
    return wg_slim_container["base_url"]


@pytest.fixture
def create_authenticated_session(container_simple):
    """Return an authenticated `requests.Session` for integration tests.

    Uses the `container_simple` fixture to locate the server and a fixed test password.
    """
    session = requests.Session()
    response = session.post(f"{container_simple}/api/login", json={"password": "testpassword123"})
    assert response.status_code == 200, f"Auth failed: {response.text}"
    token = response.json().get("access_token")
    session.headers.update({"Authorization": f"Bearer {token}"})
    return session
