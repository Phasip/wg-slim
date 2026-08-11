"""Regression tests for config consistency, rollback and atomic persistence.

Every mutation path funnels through `SyncedConfigManager.save()`. These tests
pin down that a rejected or failed save leaves both the file on disk and the
in-memory config exactly as they were.
"""

import os

import pytest
import yaml

import config_model
from config_model import ConfigValidationError, SyncedConfigManager

BASE_CONFIG = {
    "basic": {"password": "pw", "bind_addr": "5000"},
    "server": {"name": "server", "interface_name": "wg0"},
    "peers": [
        {
            "name": "server",
            "interface": "Address = 10.30.0.1/24\nListenPort = 51820\nPrivateKey = SRVKEY",
            "as_peer": "PublicKey = SRVPUB\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0",
            "enabled": True,
            "default": True,
        },
        {
            "name": "alice",
            "interface": "Address = 10.30.0.2/32\nPrivateKey = ALICEKEY",
            "as_peer": "PublicKey = ALICEPUB\nAllowedIPs = 10.30.0.2/32",
            "enabled": True,
            "default": False,
        },
    ],
}


def write_config(tmp_path, config=None, name="config.yaml"):
    path = tmp_path / name
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(config if config is not None else BASE_CONFIG, f)
    os.chmod(path, 0o600)
    return str(path)


@pytest.fixture
def manager(tmp_path):
    return SyncedConfigManager(write_config(tmp_path))


def peer_yaml(manager, peer_name, **overrides):
    """Return the peer's YAML with `overrides` applied - what the UI editor sends."""
    data = yaml.safe_load(config_model.ConfigHelper.to_yaml(config_model.get_peer(manager.config, peer_name)))
    data.update(overrides)
    return yaml.dump(data)


def on_disk(manager):
    with open(manager.file_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestPeerRenameInvariants:
    """Renaming a peer must never leave the instance in a broken state."""

    def test_renaming_server_peer_is_rejected(self, manager):
        with pytest.raises(ConfigValidationError, match="must match an existing peer"):
            manager.update_peer_from_yaml("server", peer_yaml(manager, "server", name="renamed"))

        assert [p.name for p in manager.config.peers] == ["server", "alice"]
        assert [p["name"] for p in on_disk(manager)["peers"]] == ["server", "alice"]

    def test_instance_still_usable_after_rejected_rename(self, manager):
        with pytest.raises(ConfigValidationError):
            manager.update_peer_from_yaml("server", peer_yaml(manager, "server", name="renamed"))

        # These all raised PeerNotFoundException (HTTP 404/500) before the fix
        assert "SRVKEY" in manager.generate_server_config(manager.config.server.name)
        manager.add_peer("bob")
        assert "bob" in [p.name for p in manager.config.peers]

    def test_renaming_a_peer_onto_another_name_is_rejected(self, manager):
        with pytest.raises(ConfigValidationError, match="Duplicate peer name"):
            manager.update_peer_from_yaml("alice", peer_yaml(manager, "alice", name="server"))

        assert [p.name for p in manager.config.peers] == ["server", "alice"]
        assert [p["name"] for p in on_disk(manager)["peers"]] == ["server", "alice"]
        # alice must still be handed out to the WireGuard server config
        assert "ALICEPUB" in manager.generate_server_config("server")

    def test_ordinary_rename_still_works(self, manager):
        manager.update_peer_from_yaml("alice", peer_yaml(manager, "alice", name="alice2"))
        assert [p["name"] for p in on_disk(manager)["peers"]] == ["server", "alice2"]


class TestSaveRollback:
    """A failing watcher must not leave a half-applied config in memory."""

    def test_watcher_failure_restores_in_memory_config(self, manager):
        def exploding_watcher():
            raise RuntimeError("sync failed")

        manager.add_on_config_change(exploding_watcher)
        peer = config_model.get_peer(manager.config, "alice")
        peer.enabled = False

        with pytest.raises(RuntimeError):
            manager.save()

        # Reloaded from disk, so the rejected change is gone from memory too
        assert config_model.get_peer(manager.config, "alice").enabled is True
        assert on_disk(manager)["peers"][1]["enabled"] is True

    def test_config_sync_exception_still_rolls_back(self, manager):
        def failing_watcher():
            raise config_model.ConfigSyncException("nft failed")

        manager.add_on_config_change(failing_watcher)
        config_model.get_peer(manager.config, "alice").enabled = False

        with pytest.raises(config_model.ConfigSyncException):
            manager.save()

        assert config_model.get_peer(manager.config, "alice").enabled is True


class TestAtomicWrite:
    def test_config_is_written_atomically_with_private_mode(self, manager, tmp_path):
        os.remove(manager.file_path)
        manager.save()

        mode = os.stat(manager.file_path).st_mode & 0o777
        assert mode == 0o600, f"recreated config is {oct(mode)}, private keys must stay 0600"
        assert "PrivateKey" in open(manager.file_path).read()

    def test_no_temporary_files_are_left_behind(self, manager, tmp_path):
        manager.save()
        leftovers = [p.name for p in tmp_path.iterdir() if p.name != "config.yaml"]
        assert leftovers == []

    def test_failed_save_leaves_previous_file_intact(self, manager):
        before = open(manager.file_path, encoding="utf-8").read()

        manager.add_on_config_change(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
        config_model.get_peer(manager.config, "alice").enabled = False
        with pytest.raises(RuntimeError):
            manager.save()

        assert open(manager.file_path, encoding="utf-8").read() == before


class TestAddPeerAddressHandling:
    def test_dual_stack_server_address(self, tmp_path):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["peers"][0]["interface"] = "Address = 10.30.0.1/24, fd00::1/64\nListenPort = 51820\nPrivateKey = SRVKEY"
        manager = SyncedConfigManager(write_config(tmp_path, config))

        peer = manager.add_peer("bob")
        assert "10.30.0." in peer.interface

    def test_peer_without_address_does_not_block_allocation(self, tmp_path):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["peers"].append({"name": "broken", "interface": "PrivateKey = X", "as_peer": "PublicKey = Y", "enabled": True, "default": False})
        manager = SyncedConfigManager(write_config(tmp_path, config))

        assert manager.add_peer("bob") is not None

    def test_unparseable_address_is_skipped(self, tmp_path):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["peers"][1]["interface"] = "Address = not-an-ip\nPrivateKey = ALICEKEY"
        manager = SyncedConfigManager(write_config(tmp_path, config))

        assert manager.add_peer("bob") is not None

    def test_exhausted_pool_raises_validation_error(self, tmp_path):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        # /30 leaves exactly two usable hosts: the server and one peer
        config["peers"][0]["interface"] = "Address = 10.30.0.1/30\nListenPort = 51820\nPrivateKey = SRVKEY"
        config["peers"][1]["interface"] = "Address = 10.30.0.2/32\nPrivateKey = ALICEKEY"
        manager = SyncedConfigManager(write_config(tmp_path, config))

        with pytest.raises(ConfigValidationError, match="No free addresses"):
            manager.add_peer("bob")

    def test_server_without_address_raises_validation_error(self, tmp_path):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["peers"][0]["interface"] = "ListenPort = 51820\nPrivateKey = SRVKEY"
        manager = SyncedConfigManager(write_config(tmp_path, config))

        with pytest.raises(ConfigValidationError, match="no Address"):
            manager.add_peer("bob")

    def test_invalid_server_address_raises_validation_error(self, tmp_path):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["peers"][0]["interface"] = "Address = nonsense\nPrivateKey = SRVKEY"
        manager = SyncedConfigManager(write_config(tmp_path, config))

        with pytest.raises(ConfigValidationError, match="invalid Address"):
            manager.add_peer("bob")


class TestRawConfigInput:
    """Malformed API input must be a 400 (ConfigValidationError), never a 500."""

    @pytest.mark.parametrize(
        "payload",
        [
            "server:\n  name: server\n  interface_name: wg0\npeers: []\n",  # no 'basic'
            "just-a-string\n",
            "- a\n- b\n",
            "",
            "basic: not-a-mapping\nserver: {}\npeers: []\n",
        ],
    )
    def test_malformed_documents_are_rejected(self, manager, payload):
        with pytest.raises(ConfigValidationError):
            manager.set_raw_config(payload, ignore_password=True)

        assert [p.name for p in manager.config.peers] == ["server", "alice"]

    def test_duplicate_peer_names_are_rejected(self, manager):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["peers"][1]["name"] = "server"

        with pytest.raises(ConfigValidationError, match="Duplicate peer name"):
            manager.set_raw_config(yaml.dump(config), ignore_password=True)

        assert [p["name"] for p in on_disk(manager)["peers"]] == ["server", "alice"]

    def test_valid_config_is_accepted(self, manager):
        config = yaml.safe_load(yaml.dump(BASE_CONFIG))
        config["server"]["interface_name"] = "wg7"
        manager.set_raw_config(yaml.dump(config), ignore_password=True)
        assert manager.config.server.interface_name == "wg7"


class TestYamlAliasBomb:
    """Aliases let a tiny document expand into a huge object graph."""

    BOMB = 'a: &a ["x","x","x","x","x","x","x","x","x"]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n'

    def test_config_put_rejects_aliases(self, manager):
        with pytest.raises(ConfigValidationError, match="aliases"):
            manager.set_raw_config(self.BOMB, ignore_password=True)

    def test_peer_yaml_rejects_aliases(self, manager):
        with pytest.raises(ConfigValidationError, match="aliases"):
            manager.update_peer_from_yaml("alice", self.BOMB)

    def test_invalid_yaml_is_a_validation_error(self, manager):
        with pytest.raises(ConfigValidationError, match="Invalid YAML"):
            manager.set_raw_config("basic: [unclosed\n", ignore_password=True)
