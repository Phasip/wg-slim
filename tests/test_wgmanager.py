"""Unit tests for `WgManager` and `PeerStats` using pytest fixtures."""

from wg_manager import WgManager, PeerStats


def test_peerstats_basic():
    peer = PeerStats(public_key="testkey", endpoint="1.2.3.4:51820", allowed_ips=["10.0.0.2/32"], transfer_rx=1024, transfer_tx=2048)
    assert peer.public_key == "testkey"
    assert peer.endpoint == "1.2.3.4:51820"
    assert peer.allowed_ips == ["10.0.0.2/32"]
    assert peer.transfer_rx == 1024
    assert peer.transfer_tx == 2048


def test_is_interface_up_true(mock_wg_manager):
    # Ensure the fixture will report the interface as up
    mock_wg_manager["ip link show dev wg0"] = (0, "", "")
    assert WgManager.is_interface_up("wg0") is True


def test_is_interface_up_false(mock_wg_manager):
    # Ensure the fixture will report the interface as down
    mock_wg_manager["ip link show dev wg0"] = (1, "", "")
    assert WgManager.is_interface_up("wg0") is False


def test_get_interface_stats(mock_wg_manager):
    dump_output = """privatekey123	publickey456	51820	off
peerpubkey1	(none)	1.2.3.4:51820	10.0.0.2/32	1733745600	1024	2048	off
peerpubkey2	(none)	(none)	10.0.0.3/32	0	0	0	25
"""
    mock_wg_manager["wg show wg0 dump"] = (0, dump_output, "")

    stats = WgManager.get_interface_stats("wg0")

    assert stats.name == "wg0"
    assert stats.private_key == "privatekey123"
    assert stats.public_key == "publickey456"
    assert stats.listening_port == 51820
    assert len(stats.peers) == 2

    peer1 = stats.peers[0]
    assert peer1.public_key == "peerpubkey1"
    assert peer1.endpoint == "1.2.3.4:51820"
    assert peer1.allowed_ips == ["10.0.0.2/32"]
    assert peer1.transfer_rx == 1024
    assert peer1.transfer_tx == 2048


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
