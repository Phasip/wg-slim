"""Tests for password change and settings API."""

import pytest
import yaml
import wgslim_api_client
from pydantic import ValidationError
from wgslim_api_client.exceptions import (
    UnauthorizedException,
    ForbiddenException,
    BadRequestException,
    NotFoundException,
)


class TestPasswordChange:
    """Tests for password change endpoint."""

    def test_change_password_success(self, generated_api_client, config_for_test_client):
        """Test successful password change."""
        response = generated_api_client.settings_password_put(
            wgslim_api_client.SettingsPasswordPutRequest(
                current_password="testpassword",
                new_password="new_secure_password",
                confirm_password="new_secure_password",
            )
        )
        assert response.message == ""

        with open(config_for_test_client, "r") as f:
            config = yaml.safe_load(f)
        assert config["basic"]["password"] == "new_secure_password"

    def test_change_password_missing_field(self, generated_api_client):
        """Test password change with missing field."""
        with pytest.raises(ValidationError):
            generated_api_client.settings_password_put(wgslim_api_client.SettingsPasswordPutRequest(current_password="", new_password="", confirm_password=""))

    def test_change_password_requires_auth(self, generated_unauth_api_client):
        """Test password change requires authentication."""
        with pytest.raises(UnauthorizedException):
            generated_unauth_api_client.settings_password_put(wgslim_api_client.SettingsPasswordPutRequest(current_password="wrong", new_password="test1234", confirm_password="test1234"))

    def test_change_password_wrong_current(self, generated_api_client, config_for_test_client):
        """Authenticated request with wrong current password should be rejected."""
        with pytest.raises(ForbiddenException):
            generated_api_client.settings_password_put(wgslim_api_client.SettingsPasswordPutRequest(current_password="wrong_password", new_password="newpw", confirm_password="newpw"))

        with open(config_for_test_client, "r") as f:
            config = yaml.safe_load(f)
        assert config["basic"]["password"] == "testpassword"

    def test_change_password_confirm_mismatch(self, generated_api_client, config_for_test_client):
        """New password and confirm must match."""
        with pytest.raises(BadRequestException):
            generated_api_client.settings_password_put(wgslim_api_client.SettingsPasswordPutRequest(current_password="testpassword", new_password="a", confirm_password="b"))

        with open(config_for_test_client, "r") as f:
            config = yaml.safe_load(f)
        assert config["basic"]["password"] == "testpassword"


class TestRawConfigAPI:
    """Tests for raw config API endpoints."""

    def test_get_raw_config(self, generated_api_client):
        """Get raw config via /api/config."""
        response = generated_api_client.config_get()

        assert response.config is not None
        assert "server:" in response.config

    def test_set_raw_config_success(self, generated_api_client):
        """Test setting raw config successfully."""
        # New-style config: server is minimal; server peer holds interface/as_peer
        new_config = """
basic:
  password: test
  bind_addr: "5000"
server:
  name: server
  interface_name: wg0
peers:
  - name: server
    interface: |
      Address = 10.0.0.1/24
      ListenPort = 51820
      PrivateKey = TESTKEY123
    as_peer: |
      PublicKey = PUBKEY123
      Endpoint = test:51820
"""
        response = generated_api_client.config_put(wgslim_api_client.ConfigPutRequest(yaml=new_config))

        assert response.message == ""

    def test_set_raw_config_invalid(self, generated_api_client):
        """Test setting invalid raw config."""
        with pytest.raises(BadRequestException):
            generated_api_client.config_put(wgslim_api_client.ConfigPutRequest(yaml="invalid: : yaml"))

    def test_set_raw_config_missing_field(self, generated_api_client):
        """Test setting raw config without config field."""
        with pytest.raises(ValidationError):
            generated_api_client.config_put(None)


class TestPeerEnableDisableAPI:
    """Tests for peer enable/disable API endpoints."""

    def test_disable_peer(self, generated_api_client, config_for_test_client):
        """Test disabling a peer."""
        generated_api_client.peers_peer_name_disable_post("peer1")

        with open(config_for_test_client, "r") as f:
            config = yaml.safe_load(f)
        # Find the peer named 'peer1' (server peer is now first)
        peer1 = next(p for p in config["peers"] if p["name"] == "peer1")
        assert peer1["enabled"] is False

    def test_enable_peer(self, generated_api_client, config_for_test_client):
        """Test enabling a peer."""
        generated_api_client.peers_peer_name_disable_post("peer1")

        generated_api_client.peers_peer_name_enable_post("peer1")

        with open(config_for_test_client, "r") as f:
            config = yaml.safe_load(f)
        peer1 = next(p for p in config["peers"] if p["name"] == "peer1")
        assert peer1["enabled"] is True

    def test_disable_nonexistent_peer(self, generated_api_client):
        """Test disabling a nonexistent peer."""
        with pytest.raises(NotFoundException):
            generated_api_client.peers_peer_name_disable_post("nonexistent")


class TestImportWgConfig:
    """Tests for importing WireGuard wg0.conf."""

    def test_import_wg_config_success(self, mock_wg_manager, generated_api_client, config_for_test_client):
        """Test successful import of wg0.conf."""
        mock_wg_manager["wg pubkey"] = (0, "SERVER_PUBLIC_KEY\\n", "")
        base_config = """basic:
  password: test
  bind_addr: "5000"
server:
    name: server
    interface_name: wg0
peers:
  - name: server
    interface: |
      Address = 10.0.0.1/24
      ListenPort = 51820
      PrivateKey = TESTKEY123
    as_peer: |
      PublicKey = PUBKEY123
      Endpoint = test:51820
"""
        generated_api_client.config_put(wgslim_api_client.ConfigPutRequest(yaml=base_config))

        wg_config = """[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = SERVER_PRIVATE_KEY
DNS = 1.1.1.1

[Peer]
PublicKey = PEER1_PUBLIC_KEY
AllowedIPs = 10.0.0.4/32

[Peer]
PublicKey = PEER2_PUBLIC_KEY
AllowedIPs = 10.0.0.5/32
PersistentKeepalive = 25
"""

        response = generated_api_client.config_import_wg_post(wgslim_api_client.ConfigImportWgPostRequest(wg_config=wg_config, endpoint="vpn.example.com:51820"))

        assert response.message is not None

        with open(config_for_test_client, "r") as f:
            config = yaml.safe_load(f)
        print(config)
        assert config["server"]["interface_name"] == "wg0"
        assert "SERVER_PRIVATE_KEY" in config["peers"][0]["interface"]
        assert "SERVER_PUBLIC_KEY" in config["peers"][0]["as_peer"]
        assert "vpn.example.com:51820" in config["peers"][0]["as_peer"]

        # Ensure the imported peer was added (find by generated name)
        imported_peer = next(p for p in config["peers"] if p["name"] == "peer1")
        assert "PEER1_PUBLIC_KEY" in imported_peer["as_peer"]
        assert "UNKNOWN_PRIVATEKEY" in imported_peer["interface"]

        assert config["basic"]["password"] == "testpassword"

    def test_import_wg_config_missing_config(self, generated_api_client):
        """Test import with missing wg_config."""
        with pytest.raises(ValidationError):
            generated_api_client.config_import_wg_post(wgslim_api_client.ConfigImportWgPostRequest(wg_config=None, endpoint="server:51820"))

    def test_import_wg_config_missing_endpoint(self, generated_api_client):
        """Test import with missing endpoint."""
        with pytest.raises(ValidationError):
            generated_api_client.config_import_wg_post(wgslim_api_client.ConfigImportWgPostRequest(wg_config="[Interface]\nAddress = 10.0.0.1/24", endpoint=None))

    def test_import_wg_config_no_interface(self, generated_api_client):
        """Test import with no Interface section."""
        with pytest.raises(BadRequestException):
            generated_api_client.config_import_wg_post(wgslim_api_client.ConfigImportWgPostRequest(wg_config="[Peer]\nPublicKey = KEY", endpoint="server:51820"))

    def test_import_wg_config_missing_private_key(self, generated_api_client):
        """Test import with missing server private key."""
        with pytest.raises(BadRequestException):
            generated_api_client.config_import_wg_post(wgslim_api_client.ConfigImportWgPostRequest(wg_config="[Interface]\nAddress = 10.0.0.1/24", endpoint="server:51820"))
