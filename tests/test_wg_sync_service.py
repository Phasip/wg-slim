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
        # `fail_on` is matched against "<call> <argument>", e.g. "up" or "up /x/wg1.conf"
        if self.fail_on is not None and f"{name} {arg}".startswith(self.fail_on):
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


def peer_only_change(manager):
    """Change something `wg syncconf` can apply: a client peer's keepalive."""
    manager.update_peer_from_yaml("alice", "name: alice\ninterface: |\n  Address = 10.30.0.2/32\n  PrivateKey = ALICEKEY\nas_peer: |\n  PublicKey = ALICEPUB\n  AllowedIPs = 10.30.0.2/32\n  PersistentKeepalive = 15\n")


def test_first_sync_brings_interface_up(service, fake_wg):
    service.sync_now()
    assert fake_wg.calls == [("up", service.output_dir + "/wg0.conf")]


def test_peer_change_uses_syncconf_without_restart(service, fake_wg):
    service.sync_now()
    fake_wg.calls.clear()
    service.config_manager.add_on_config_change(service.sync_now)
    peer_only_change(service.config_manager)
    assert fake_wg.calls == [("syncconf", "wg0")]


def test_interface_change_restarts_interface(service, fake_wg):
    service.sync_now()
    fake_wg.calls.clear()
    service.config_manager.add_on_config_change(service.sync_now)
    service.config_manager.update_peer_from_yaml(
        "server",
        "name: server\ninterface: |\n  Address = 10.30.0.1/24\n  ListenPort = 51820\n  PrivateKey = SRVKEY\n  MTU = 1380\nas_peer: |\n  PublicKey = SRVPUB\n  Endpoint = vpn.example.com:51820\n  AllowedIPs = 0.0.0.0/0\ndefault: true\n",
    )
    conf = service.output_dir + "/wg0.conf"
    assert fake_wg.calls == [("down", conf), ("up", conf)]
    with open(conf, encoding="utf-8") as f:
        assert "MTU = 1380" in f.read()


def test_interface_up_without_known_config_is_restarted(service, fake_wg):
    """An interface that is already up with an unknown config gets restarted once."""
    fake_wg.up.add("wg0")
    service.sync_now()
    conf = service.output_dir + "/wg0.conf"
    assert fake_wg.calls == [("down", conf), ("up", conf)]


def test_failed_rename_brings_old_interface_back(service, fake_wg):
    manager = service.config_manager
    manager.add_on_config_change(service.sync_now)
    service.sync_now()
    fake_wg.calls.clear()

    fake_wg.fail_on = f"up {service.output_dir}/wg1.conf"
    raw = manager.get_raw_config().replace("interface_name: wg0", "interface_name: wg1")
    with pytest.raises(ConfigSyncException):
        manager.set_raw_config(raw)
    fake_wg.fail_on = None

    # wg1 failed to come up; the rollback re-synced wg0 back up
    assert manager.config.server.interface_name == "wg0"
    assert fake_wg.up == {"wg0"}
