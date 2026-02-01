#!/usr/bin/env python3
"""Convert a wg-easy wg.json file to wg-slim config.yaml format.

Usage:
    python from_wgeasy.py <wg.json> <endpoint> [password]

Arguments:
    wg.json: Path to the wg-easy JSON configuration file
    endpoint: Server endpoint (e.g., vpn.example.com:51820 or 192.168.1.1:51820)
    password: Optional admin password (default: randomly generated)

Example:
    python from_wgeasy.py /path/to/wg.json vpn.example.com:51820
    python from_wgeasy.py wg.json 192.168.1.1:51820 mysecretpass

The wg-easy JSON format looks like:
{
  "server": {
    "privateKey": "...",
    "publicKey": "...",
    "address": "10.9.0.1"
  },
  "clients": {
    "uuid1": {
      "id": "uuid1",
      "name": "client1",
      "address": "10.9.0.2",
      "privateKey": "...",
      "publicKey": "...",
      "preSharedKey": "...",
      "createdAt": "...",
      "updatedAt": "...",
      "enabled": true
    },
    ...
  }
}
"""

import sys
import json
import secrets
from typing import Any
import yaml


def build_wg_section(values: dict[str, str]) -> str:
    """Build a WireGuard config section from key-value pairs."""
    return "\n".join(f"{k} = {v}" for k, v in values.items())


def generate_random_password(length: int = 16) -> str:
    """Return a random password of specified length."""
    return secrets.token_urlsafe(length)[:length]


def parse_wgeasy_json(json_data: dict[str, Any], endpoint: str) -> dict[str, Any]:
    """Parse a wg-easy JSON file and return config dict for wg-slim."""
    server_data = json_data.get("server")
    if not server_data:
        raise ValueError("No server section found in JSON")

    server_private_key = server_data.get("privateKey")
    server_public_key = server_data.get("publicKey")
    server_address = server_data.get("address")

    if not server_private_key or not server_public_key or not server_address:
        raise ValueError("Server section missing required fields (privateKey, publicKey, address)")

    # Extract listen port from the endpoint if present, otherwise default to 51820
    listen_port = "51820"
    if ":" in endpoint:
        listen_port = endpoint.split(":")[-1]

    # Build server interface config
    server_interface_dict: dict[str, str] = {
        "Address": f"{server_address}/24",
        "ListenPort": listen_port,
        "PrivateKey": server_private_key,
    }
    server_interface = build_wg_section(server_interface_dict)

    # Build server as_peer config
    server_as_peer_dict: dict[str, str] = {
        "PublicKey": server_public_key,
        "Endpoint": endpoint,
        "AllowedIPs": "0.0.0.0/0",
        "PersistentKeepalive": "25",
    }
    server_as_peer = build_wg_section(server_as_peer_dict)

    server: dict[str, str] = {"name": "server", "interface_name": "wg0"}

    peers: list[dict[str, str | bool]] = []

    # Add server as first peer
    server_peer: dict[str, str | bool] = {"name": "server", "interface": server_interface, "as_peer": server_as_peer, "enabled": True, "default": True}
    peers.append(server_peer)

    # Parse clients/peers
    clients = json_data.get("clients", {})
    for client_id, client_data in clients.items():
        client_name = client_data.get("name", client_id)
        client_address = client_data.get("address")
        client_private_key = client_data.get("privateKey")
        client_public_key = client_data.get("publicKey")
        client_preshared_key = client_data.get("preSharedKey")
        client_enabled = client_data.get("enabled", True)

        if not client_address or not client_public_key:
            continue

        # Build peer interface config
        peer_interface_dict: dict[str, str] = {
            "Address": f"{client_address}/32",
        }
        if client_private_key:
            peer_interface_dict["PrivateKey"] = client_private_key
        else:
            peer_interface_dict["PrivateKey"] = "UNKNOWN_PRIVATEKEY"

        peer_interface = build_wg_section(peer_interface_dict)

        # Build peer as_peer config
        peer_as_peer_dict: dict[str, str] = {
            "PublicKey": client_public_key,
            "AllowedIPs": f"{client_address}/32",
        }
        if client_preshared_key:
            peer_as_peer_dict["PresharedKey"] = client_preshared_key

        peer_as_peer = build_wg_section(peer_as_peer_dict)

        peer: dict[str, str | bool] = {"name": client_name, "interface": peer_interface, "as_peer": peer_as_peer, "enabled": client_enabled, "default": False}
        peers.append(peer)

    return {"server": server, "peers": peers}


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    json_path = sys.argv[1]
    endpoint = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) > 3 else generate_random_password()

    try:
        with open(json_path, "r") as f:
            json_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File not found: {json_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    parsed = parse_wgeasy_json(json_data, endpoint)

    config: dict[str, Any] = {"basic": {"password": password, "bind_addr": "5000"}, "server": parsed["server"], "peers": parsed["peers"]}

    yaml_output = yaml.dump(config, default_flow_style=False, sort_keys=False)
    print(yaml_output)

    if len(sys.argv) <= 3:
        print(f"\n# Generated password: {password}", file=sys.stderr)
        print("# Save this password - you'll need it to log in!", file=sys.stderr)


if __name__ == "__main__":
    main()
