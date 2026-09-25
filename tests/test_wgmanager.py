"""Unit tests for `WgManager` using pytest fixtures."""

from wg_manager import WgManager


def test_is_interface_up_true(mock_wg_manager):
    # Ensure the fixture will report the interface as up
    mock_wg_manager["ip link show dev wg0"] = (0, "", "")
    assert WgManager.is_interface_up("wg0") is True


def test_is_interface_up_false(mock_wg_manager):
    # Ensure the fixture will report the interface as down
    mock_wg_manager["ip link show dev wg0"] = (1, "", "")
    assert WgManager.is_interface_up("wg0") is False


def test_get_wg_show_peer_blocks(mock_wg_manager):
    out = """interface: wg0
peer: peer1
some line
peer: peer2
other line
"""
    mock_wg_manager["wg show wg0"] = (0, out, "")
    blocks = WgManager.get_wg_show_peer_blocks("wg0")
    assert "peer1" in blocks
    assert "some line" in blocks["peer1"]
    assert "peer2" in blocks


def test_get_pubkey(mock_wg_manager):
    mock_wg_manager["wg pubkey"] = (0, "PUBKEY\n", "")
    pk = WgManager.get_pubkey("privkey")
    assert pk == "PUBKEY"


def test_generate_keypair(mock_wg_manager):
    mock_wg_manager["wg genkey"] = (0, "privkey\n", "")
    mock_wg_manager["wg pubkey"] = (0, "pubkey\n", "")
    priv, pub = WgManager.generate_keypair()
    assert priv == "privkey"
    assert pub == "pubkey"


def test_bring_up(mock_wg_manager):
    conf = "test.conf"
    mock_wg_manager[f"wg-quick up {conf}"] = (0, "", "")
    # Should not raise
    WgManager.bring_up(conf)
