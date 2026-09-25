"""Tests for `basic.password_hash`, the hashed alternative to `basic.password`."""

import copy
from unittest.mock import patch

import pytest
import yaml
from fastapi.testclient import TestClient

import wg_api
import wg_utils
from config_model import ConfigValidationError, SyncedConfigManager
from tests.conftest import _MockSyncService
from tests.test_config_integrity import BASE_CONFIG, on_disk, write_config

HASH = wg_utils.hash_password("hashed-pw")


def config_with(**basic):
    config = copy.deepcopy(BASE_CONFIG)
    config["basic"] = {"bind_addr": "5000", **basic}
    return config


@pytest.fixture
def hashed_manager(tmp_path):
    return SyncedConfigManager(write_config(tmp_path, config_with(password_hash=HASH)))


@pytest.fixture
def hashed_client(tmp_path):
    app = wg_api.create_app(sync_service=_MockSyncService(), config_file=write_config(tmp_path, config_with(password_hash=HASH)))
    return TestClient(app)


def login(client, password):
    return client.post("/api/login", json={"password": password})


class TestHashing:
    def test_verify_roundtrip(self):
        assert wg_utils.verify_password("hashed-pw", HASH)
        assert not wg_utils.verify_password("wrong", HASH)

    def test_hashes_are_salted(self):
        assert wg_utils.hash_password("x") != wg_utils.hash_password("x")

    @pytest.mark.parametrize("bad", ["", "plain", "scrypt$3$8$1$AAAA$AAAA", "scrypt$16384$8$1$!!$AAAA", "bcrypt$1$1$1$AAAA$AAAA"])
    def test_malformed_hashes_are_rejected(self, bad):
        with pytest.raises(ValueError):
            wg_utils.validate_password_hash(bad)


class TestConfigRules:
    def test_both_password_and_hash_is_an_error(self, tmp_path):
        with pytest.raises(ConfigValidationError, match="not both"):
            SyncedConfigManager(write_config(tmp_path, config_with(password="pw", password_hash=HASH)))

    def test_neither_password_nor_hash_is_an_error(self, tmp_path):
        with pytest.raises(ConfigValidationError, match="must be set"):
            SyncedConfigManager(write_config(tmp_path, config_with()))

    def test_unusable_hash_is_an_error(self, tmp_path):
        with pytest.raises(ConfigValidationError):
            SyncedConfigManager(write_config(tmp_path, config_with(password_hash="scrypt$3$8$1$AAAA$AAAA")))

    def test_plain_password_config_gets_no_hash_field(self, tmp_path):
        manager = SyncedConfigManager(write_config(tmp_path))
        manager.save()
        assert on_disk(manager)["basic"] == {"password": "pw", "bind_addr": "5000"}

    def test_initial_config_with_hash_generates_no_password(self, tmp_path, capsys):
        initial = yaml.dump({"basic": {"bind_addr": "5000", "password_hash": HASH}, "server": {"interface_name": "wg0"}})
        with patch("config_model.WgManager.generate_keypair", return_value=("PRIV", "PUB")):
            manager = SyncedConfigManager.load_or_create(str(tmp_path / "new.yaml"), initial)
        assert "password" not in on_disk(manager)["basic"]
        assert "Web management password" not in capsys.readouterr().out


class TestApi:
    def test_login_with_hash(self, hashed_client):
        assert login(hashed_client, "hashed-pw").status_code == 200
        assert login(hashed_client, "wrong").status_code == 403

    def test_password_change_keeps_hash_form(self, hashed_client, tmp_path):
        token = login(hashed_client, "hashed-pw").json()["access_token"]
        response = hashed_client.put(
            "/api/settings/password",
            json={"current_password": "hashed-pw", "new_password": "new-pw", "confirm_password": "new-pw"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

        with open(tmp_path / "config.yaml", encoding="utf-8") as f:
            basic = yaml.safe_load(f)["basic"]
        assert "password" not in basic
        assert wg_utils.verify_password("new-pw", basic["password_hash"])
        assert login(hashed_client, "new-pw").status_code == 200

    def test_config_editor_censors_and_preserves_hash(self, hashed_client, tmp_path):
        headers = {"Authorization": f"Bearer {login(hashed_client, 'hashed-pw').json()['access_token']}"}
        raw = hashed_client.get("/api/config", headers=headers).json()["config"]
        basic = yaml.safe_load(raw)["basic"]
        assert basic == {"password_hash": "PASSWORD_NOT_CHANGEABLE_IN_CONF_EDITOR", "bind_addr": "5000"}

        assert hashed_client.put("/api/config", json={"yaml": raw}, headers=headers).status_code == 200
        with open(tmp_path / "config.yaml", encoding="utf-8") as f:
            assert yaml.safe_load(f)["basic"]["password_hash"] == HASH
