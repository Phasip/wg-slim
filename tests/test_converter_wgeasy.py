"""Tests for the wg-easy JSON -> wg-slim YAML converter.

The converter output is validated against the `WireGuardConfig` schema in
`openapi.yaml`, so a config produced by the converter is guaranteed to be
loadable by wg-slim itself.
"""

import json
import os
import subprocess
import sys

import jsonschema
import pytest
import yaml

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONVERTER = os.path.join(REPO_ROOT, "converters", "from_wgeasy_old.py")
sys.path.insert(0, os.path.join(REPO_ROOT, "converters"))

import from_wgeasy_old  # noqa: E402

WGEASY_JSON = {
    "server": {
        "privateKey": "AAAA",
        "publicKey": "BBBB",
        "address": "10.30.0.1",
    },
    "clients": {
        "4aaf13e4-0dd9-4d5b-b641-08d0b064be0d": {
            "id": "4aaf13e4-0dd9-4d5b-b641-08d0b064be0d",
            "name": "barkarby",
            "address": "10.30.0.102",
            "privateKey": "XXXX",
            "publicKey": "YYY",
            "preSharedKey": "ZZZZ",
            "createdAt": "2024-07-19T21:10:15Z",
            "updatedAt": "2024-07-19T21:10:15Z",
            "enabled": True,
            "allowedIPs": "10.30.102.0/24",
        },
        "5bbf13e4-0dd9-4d5b-b641-08d0b064be0e": {
            "id": "5bbf13e4-0dd9-4d5b-b641-08d0b064be0e",
            "name": "TestPeer2",
            "address": "10.30.0.103",
            "privateKey": "PPPP",
            "publicKey": "QQQQ",
            "preSharedKey": None,
            "createdAt": "2024-07-19T21:10:15Z",
            "updatedAt": "2024-07-19T21:10:15Z",
            "enabled": False,
        },
    },
}


def _parsed():
    return from_wgeasy_old.parse_wgeasy_json(WGEASY_JSON, "vpn.example.com:51820")


def _peer(parsed, name):
    return next(p for p in parsed["peers"] if p["name"] == name)


def _section(peer, key):
    values = {}
    for line in peer[key].splitlines():
        k, v = line.split("=", 1)
        values[k.strip()] = v.strip()
    return values


@pytest.fixture(scope="module")
def openapi_schema():
    with open(os.path.join(REPO_ROOT, "openapi.yaml")) as f:
        return yaml.safe_load(f)


def test_output_validates_against_openapi_schema(openapi_schema):
    """A converted config must satisfy the WireGuardConfig schema."""
    parsed = _parsed()
    config = {"basic": {"password": "secretpw", "bind_addr": "5000"}, "server": parsed["server"], "peers": parsed["peers"]}

    # Embed components so the internal '#/components/schemas/...' $refs resolve.
    schema = dict(openapi_schema["components"]["schemas"]["WireGuardConfig"])
    schema["components"] = openapi_schema["components"]
    jsonschema.validate(instance=config, schema=schema)


def test_server_peer_matches_server_name():
    """wg-slim requires a peer whose name equals server.name."""
    parsed = _parsed()
    assert any(p["name"] == parsed["server"]["name"] for p in parsed["peers"])


def test_site_to_site_allowed_ips_are_kept():
    """The per-client allowedIPs subnet must be routed to that peer."""
    peer = _peer(_parsed(), "barkarby")
    assert _section(peer, "as_peer")["AllowedIPs"] == "10.30.0.102/32, 10.30.102.0/24"
    assert _section(peer, "interface")["Address"] == "10.30.0.102/32"
    assert _section(peer, "as_peer")["PresharedKey"] == "ZZZZ"
    assert peer["enabled"] is True


def test_client_without_allowed_ips_gets_own_address_only():
    peer = _peer(_parsed(), "TestPeer2")
    as_peer = _section(peer, "as_peer")
    assert as_peer["AllowedIPs"] == "10.30.0.103/32"
    assert "PresharedKey" not in as_peer
    assert peer["enabled"] is False


def test_names_are_sanitized_and_unique():
    """Names that wg-slim would reject are rewritten, and stay unique."""
    data = {
        "server": WGEASY_JSON["server"],
        "clients": {
            "id-1": {"name": "my laptop!", "address": "10.30.0.2", "publicKey": "K1"},
            "id-2": {"name": "my/laptop", "address": "10.30.0.3", "publicKey": "K2"},
            "id-3": {"name": "", "address": "10.30.0.4", "publicKey": "K3"},
        },
    }
    parsed = from_wgeasy_old.parse_wgeasy_json(data, "vpn.example.com:51820")
    names = [p["name"] for p in parsed["peers"]]
    assert names == ["server", "my-laptop", "my-laptop-2", "id-3"]
    assert len(set(names)) == len(names)


def test_missing_private_key_marked_unknown():
    data = {"server": WGEASY_JSON["server"], "clients": {"id-1": {"name": "nokey", "address": "10.30.0.5", "publicKey": "K1"}}}
    parsed = from_wgeasy_old.parse_wgeasy_json(data, "vpn.example.com:51820")
    assert _section(_peer(parsed, "nokey"), "interface")["PrivateKey"] == "UNKNOWN_PRIVATEKEY"


def test_server_interface_and_endpoint():
    parsed = _parsed()
    server = _peer(parsed, "server")
    interface = _section(server, "interface")
    as_peer = _section(server, "as_peer")
    assert interface["Address"] == "10.30.0.1/24"
    assert interface["ListenPort"] == "51820"
    assert interface["PrivateKey"] == "AAAA"
    assert as_peer["Endpoint"] == "vpn.example.com:51820"
    assert as_peer["AllowedIPs"] == "0.0.0.0/0"
    assert server["default"] is True


def test_server_address_with_prefix_is_not_doubled():
    data = {"server": {"privateKey": "AAAA", "publicKey": "BBBB", "address": "10.30.0.1/16"}, "clients": {}}
    parsed = from_wgeasy_old.parse_wgeasy_json(data, "vpn.example.com:51820")
    assert _section(_peer(parsed, "server"), "interface")["Address"] == "10.30.0.1/16"


def test_missing_server_section_raises():
    with pytest.raises(ValueError):
        from_wgeasy_old.parse_wgeasy_json({"clients": {}}, "vpn.example.com:51820")


def test_cli_produces_loadable_yaml(tmp_path):
    """End-to-end: the CLI writes YAML that parses back into the same config."""
    json_path = tmp_path / "wg0.json"
    json_path.write_text(json.dumps(WGEASY_JSON))

    out = subprocess.check_output([sys.executable, CONVERTER, str(json_path), "vpn.example.com:51820", "secretpw", "--dns", "1.1.1.1"], text=True)
    config = yaml.safe_load(out)

    assert config["basic"]["password"] == "secretpw"
    assert config["server"]["interface_name"] == "wg0"
    assert "DNS = 1.1.1.1" in _peer(config, "barkarby")["interface"]
    # Block scalars keep the sections readable/round-trippable
    assert "10.30.102.0/24" in _peer(config, "barkarby")["as_peer"]
