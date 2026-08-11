#!/usr/bin/env python3
"""Convert a wg-easy wg.json file to wg-slim config.yaml format.

Usage:
    python from_wgeasy_old.py <wg.json> <endpoint> [password] [options]

Arguments:
    wg.json: Path to the wg-easy JSON configuration file
    endpoint: Server endpoint (e.g., vpn.example.com:51820 or 192.168.1.1:51820)
    password: Optional admin password (default: randomly generated)

Options:
    --server-prefix N: Prefix length for the server Address (default: 24)
    --dns VALUE: DNS value to add to every client [Interface] section
    --mtu VALUE: MTU value to add to every client [Interface] section
    --interface-name NAME: WireGuard interface name (default: wg0)
    --client-allowed-ips VALUE: AllowedIPs clients use for the server (default: 0.0.0.0/0)

Example:
    python from_wgeasy_old.py /path/to/wg.json vpn.example.com:51820
    python from_wgeasy_old.py wg.json 192.168.1.1:51820 mysecretpass --dns 1.1.1.1

The wg-easy JSON format looks like:
{
  "server": {
    "privateKey": "...",
    "publicKey": "...",
    "address": "10.30.0.1"
  },
  "clients": {
    "uuid1": {
      "id": "uuid1",
      "name": "client1",
      "address": "10.30.0.102",
      "privateKey": "...",
      "publicKey": "...",
      "preSharedKey": "...",
      "createdAt": "...",
      "updatedAt": "...",
      "enabled": true,
      "allowedIPs": "10.30.102.0/24"
    },
    ...
  }
}

Notes:
- The optional per-client `allowedIPs` field (used by wg-easy forks for
  site-to-site peers) is treated as extra networks routed *to* that peer and is
  appended to the peer's `as_peer` AllowedIPs, after the client's own /32. The
  peer keeps reaching the server via the server's own AllowedIPs
  (`--client-allowed-ips`, default 0.0.0.0/0).
- Client names are sanitized to match the peer name rules enforced by wg-slim
  (`^[A-Za-z0-9_-]{1,64}$`), so names with spaces or punctuation still import.
"""

import argparse
import json
import re
import secrets
import sys
from typing import Any
import yaml

PEER_NAME_RE = re.compile(r"[^A-Za-z0-9_-]+")
MAX_PEER_NAME_LEN = 64


class _MultilineDumper(yaml.SafeDumper):
    """Dumper that renders multi-line strings as readable block scalars."""


def _str_representer(dumper: Any, data: str) -> Any:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _str_representer, Dumper=_MultilineDumper)


def build_wg_section(values: dict[str, str]) -> str:
    """Build a WireGuard config section from key-value pairs, skipping empty values."""
    return "\n".join(f"{k} = {v}" for k, v in values.items() if v)


def generate_random_password(length: int = 16) -> str:
    """Return a random password of specified length."""
    return secrets.token_urlsafe(length)[:length]


def sanitize_peer_name(raw_name: str, fallback: str, used_names: set[str]) -> str:
    """Return a unique peer name accepted by wg-slim (`^[A-Za-z0-9_-]{1,64}$`)."""
    name = PEER_NAME_RE.sub("-", raw_name).strip("-")
    if not name:
        name = PEER_NAME_RE.sub("-", fallback).strip("-")
    if not name:
        name = "peer"
    name = name[:MAX_PEER_NAME_LEN]

    candidate = name
    counter = 2
    while candidate in used_names:
        suffix = f"-{counter}"
        candidate = name[: MAX_PEER_NAME_LEN - len(suffix)] + suffix
        counter += 1
    used_names.add(candidate)
    return candidate


def _as_cidr_list(value: Any) -> list[str]:
    """Normalize an allowedIPs value (string, comma separated string, or list) to a list."""
    if not value:
        return []
    if type(value) is list:
        parts: list[str] = [str(v).strip() for v in value]  # pyright: ignore[reportUnknownVariableType, reportUnknownArgumentType]
        return [p for p in parts if p]
    return [p.strip() for p in str(value).split(",") if p.strip()]


def build_allowed_ips(client_address: str, extra_allowed: Any) -> str:
    """Return the AllowedIPs the server should route to this peer.

    The client's own address is always first; any extra networks configured in
    wg-easy (site-to-site subnets) follow, in order and without duplicates.
    """
    allowed: list[str] = [f"{client_address}/32"]
    for entry in _as_cidr_list(extra_allowed):
        if entry not in allowed:
            allowed.append(entry)
    return ", ".join(allowed)


def _address_with_prefix(address: str, prefix: str) -> str:
    """Append /prefix to an address unless it already carries one."""
    if "/" in address:
        return address
    return f"{address}/{prefix}"


def parse_wgeasy_json(
    json_data: dict[str, Any],
    endpoint: str,
    server_prefix: str = "24",
    dns: str = "",
    mtu: str = "",
    interface_name: str = "wg0",
    client_allowed_ips: str = "0.0.0.0/0",
) -> dict[str, Any]:
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
        "Address": _address_with_prefix(server_address, server_prefix),
        "ListenPort": listen_port,
        "PrivateKey": server_private_key,
    }
    server_interface = build_wg_section(server_interface_dict)

    # Build server as_peer config: this is what every client sees as its [Peer]
    server_as_peer_dict: dict[str, str] = {
        "PublicKey": server_public_key,
        "Endpoint": endpoint,
        "AllowedIPs": client_allowed_ips,
        "PersistentKeepalive": "25",
    }
    server_as_peer = build_wg_section(server_as_peer_dict)

    used_names: set[str] = set()
    server_name = sanitize_peer_name("server", "server", used_names)
    server: dict[str, str] = {"name": server_name, "interface_name": interface_name}

    peers: list[dict[str, str | bool]] = []

    # Add server as first peer
    server_peer: dict[str, str | bool] = {"name": server_name, "interface": server_interface, "as_peer": server_as_peer, "enabled": True, "default": True}
    peers.append(server_peer)

    # Parse clients/peers
    clients = json_data.get("clients", {})
    for client_id, client_data in clients.items():
        client_address = client_data.get("address")
        client_private_key = client_data.get("privateKey")
        client_public_key = client_data.get("publicKey")
        client_preshared_key = client_data.get("preSharedKey")
        client_enabled = client_data.get("enabled", True)

        if not client_address or not client_public_key:
            continue

        client_name = sanitize_peer_name(client_data.get("name") or client_id, client_id, used_names)

        # Build peer interface config
        peer_interface_dict: dict[str, str] = {
            "Address": f"{client_address}/32",
            "PrivateKey": client_private_key or "UNKNOWN_PRIVATEKEY",
            "DNS": dns,
            "MTU": mtu,
        }
        peer_interface = build_wg_section(peer_interface_dict)

        # Build peer as_peer config: what the server (and other peers) route to it
        peer_as_peer_dict: dict[str, str] = {
            "PublicKey": client_public_key,
            "AllowedIPs": build_allowed_ips(client_address, client_data.get("allowedIPs")),
            "PresharedKey": client_preshared_key or "",
        }
        peer_as_peer = build_wg_section(peer_as_peer_dict)

        peer: dict[str, str | bool] = {"name": client_name, "interface": peer_interface, "as_peer": peer_as_peer, "enabled": bool(client_enabled), "default": False}
        peers.append(peer)

    return {"server": server, "peers": peers}


def build_config(json_data: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Return the full wg-slim config dict for the parsed wg-easy JSON."""
    parsed = parse_wgeasy_json(
        json_data,
        args.endpoint,
        server_prefix=args.server_prefix,
        dns=args.dns,
        mtu=args.mtu,
        interface_name=args.interface_name,
        client_allowed_ips=args.client_allowed_ips,
    )
    return {"basic": {"password": args.password, "bind_addr": "5000"}, "server": parsed["server"], "peers": parsed["peers"]}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert a wg-easy wg.json file to a wg-slim config.yaml")
    parser.add_argument("json_path", help="Path to the wg-easy JSON file")
    parser.add_argument("endpoint", help="Server endpoint, e.g. vpn.example.com:51820")
    parser.add_argument("password", nargs="?", default=None, help="Admin password (default: randomly generated)")
    parser.add_argument("--server-prefix", default="24", help="Prefix length for the server Address (default: 24)")
    parser.add_argument("--dns", default="", help="DNS value for client [Interface] sections")
    parser.add_argument("--mtu", default="", help="MTU value for client [Interface] sections")
    parser.add_argument("--interface-name", default="wg0", help="WireGuard interface name (default: wg0)")
    parser.add_argument("--client-allowed-ips", default="0.0.0.0/0", help="AllowedIPs clients use for the server (default: 0.0.0.0/0)")
    return parser.parse_args(argv)


def main():
    args = parse_args()
    generated_password = args.password is None
    if generated_password:
        args.password = generate_random_password()

    try:
        with open(args.json_path, "r") as f:
            json_data = json.load(f)
    except FileNotFoundError:
        raise SystemExit(f"Error: File not found: {args.json_path}") from None
    except json.JSONDecodeError as e:
        raise SystemExit(f"Error: Invalid JSON: {e}") from e

    try:
        config = build_config(json_data, args)
    except ValueError as e:
        raise SystemExit(f"Error: {e}") from e

    print(yaml.dump(config, Dumper=_MultilineDumper, default_flow_style=False, sort_keys=False))

    if generated_password:
        print(f"\n# Generated password: {args.password}", file=sys.stderr)
        print("# Save this password - you'll need it to log in!", file=sys.stderr)


if __name__ == "__main__":
    main()
