"""Unit tests for WgConfigSyncService, with the WireGuard tools mocked out."""

import subprocess
from unittest.mock import patch

import pytest

from config_model import ConfigSyncException, SyncedConfigManager
from tests.test_config_integrity import write_config
from wg_sync_service import WgConfigSyncService


class FakeWg:
    """Stand-in for WgManager that records calls and tracks which interfaces are up."""

    def __init__(self, up=()):
        self.up = set(up)
        self.calls = []
        self.fail_on = None

    def _record(self, name, arg):
        self.calls.append((name, arg))
        if self.fail_on == name:
            raise subprocess.CalledProcessError(1, ["wg-quick", name, arg], output="", stderr="boom")

    def is_interface_up(self, interface):
        return interface in self.up

    def bring_up(self, config_file):
        self._record("up", config_file)
        self.up.add(config_file.rsplit("/", 1)[-1].removesuffix(".conf"))

    def bring_down(self, config_file):
        self._record("down", config_file)
        self.up.discard(config_file.rsplit("/", 1)[-1].removesuffix(".conf"))

    def sync_config(self, interface, config_file):
        self._record("syncconf", interface)


@pytest.fixture
def fake_wg():
    fake = FakeWg()
    with patch("wg_sync_service.wg_manager.WgManager", fake):
        yield fake


@pytest.fixture
def service(tmp_path, fake_wg):
    manager = SyncedConfigManager(write_config(tmp_path))
    svc = WgConfigSyncService(config_manager=manager)
    svc.output_dir = str(tmp_path / "wireguard")
    return svc


def test_command_failure_is_a_config_sync_exception(service, fake_wg):
    fake_wg.fail_on = "up"
    with pytest.raises(ConfigSyncException, match="boom"):
        service.sync_now()
