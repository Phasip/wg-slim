"""Tests for the container healthcheck script."""

import importlib
import json
import os
from unittest.mock import patch

import pytest
import yaml

import wg_utils


@pytest.mark.parametrize(
    "bind_addr,expected",
    [
        ("5000", ("0.0.0.0", 5000)),
        (":5000", ("0.0.0.0", 5000)),
        ("0.0.0.0:5000", ("0.0.0.0", 5000)),
        ("127.0.0.1:8080", ("127.0.0.1", 8080)),
    ],
)
def test_parse_bind_addr(bind_addr, expected):
    assert wg_utils.parse_bind_addr(bind_addr) == expected


def test_main_still_exposes_parse_bind_addr():
    """main.py re-exports it; keep that working for anything importing it there."""
    import main

    assert main.parse_bind_addr("5000") == ("0.0.0.0", 5000)


class _FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status = status
        self._payload = json.dumps(payload if payload is not None else {"status": "healthy"}).encode()

    def read(self, *args):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _healthcheck(tmp_path, bind_addr="5000"):
    config = {"basic": {"password": "pw", "bind_addr": bind_addr}, "server": {"name": "server", "interface_name": "wg0"}, "peers": []}
    path = tmp_path / "config.yaml"
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config, f)
    os.environ["CONFIG_FILE"] = str(path)

    import healthcheck

    return importlib.reload(healthcheck)


def test_healthcheck_passes_when_api_is_healthy(tmp_path):
    module = _healthcheck(tmp_path)
    with patch("urllib.request.urlopen", return_value=_FakeResponse()) as urlopen:
        assert module.check() is True
    assert urlopen.call_args[0][0] == "http://127.0.0.1:5000/api/health"


def test_healthcheck_uses_configured_port(tmp_path):
    module = _healthcheck(tmp_path, bind_addr="127.0.0.1:8443")
    with patch("urllib.request.urlopen", return_value=_FakeResponse()) as urlopen:
        assert module.check() is True
    assert urlopen.call_args[0][0] == "http://127.0.0.1:8443/api/health"


def test_healthcheck_fails_on_unhealthy_payload(tmp_path):
    module = _healthcheck(tmp_path)
    with patch("urllib.request.urlopen", return_value=_FakeResponse(payload={"status": "sick"})):
        assert module.check() is False


def test_healthcheck_fails_on_bad_status(tmp_path):
    module = _healthcheck(tmp_path)
    with patch("urllib.request.urlopen", return_value=_FakeResponse(status=503)):
        assert module.check() is False
