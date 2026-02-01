#!/usr/bin/env python3
"""Convert a WireGuard wg.conf file to wg-slim config.yaml format.

Usage:
    python from_wg_conf.py <wg.conf> <endpoint> [password]

Arguments:
    wg.conf: Path to the WireGuard configuration file
    endpoint: Server endpoint (e.g., vpn.example.com:51820 or 192.168.1.1:51820)
    password: Optional admin password (default: randomly generated)

Example:
    python from_wg_conf.py /etc/wireguard/wg0.conf vpn.example.com:51820
    python from_wg_conf.py wg0.conf 192.168.1.1:51820 mysecretpass
"""

import sys
import re
import subprocess
import secrets
from typing import Dict, Any
import yaml


def get_pubkey(private_key: str) -> str:
    """Derive the public key from a WireGuard private key using `wg pubkey`."""
    result = subprocess.run(["wg", "pubkey"], input=private_key.encode(), capture_output=True, check=True)
    return result.stdout.decode().strip()


def parse_wg_section(section: str) -> Dict[str, str]:
    """Parse a WireGuard config section (interface/as_peer) into key-value pairs."""
    result: Dict[str, str] = {}
    for line in section.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            result[k.strip()] = v.strip()
    return result


def build_wg_section(values: Dict[str, str]) -> str:
    """Build a WireGuard config section from key-value pairs."""
    return "\n".join(f"{k} = {v}" for k, v in values.items())


def generate_random_password(length=16) -> str:
    """Return a random password of specified length."""

    return secrets.token_urlsafe(length)[:length]


def parse_wg_conf(wg_config: str, endpoint: str) -> dict[str, Any]:
    """Parse a WireGuard configuration string and return a dict with 'server' and 'peers'."""
    pattern = re.compile(r"^\[(?P<section>[^\]]+)\]\s*$", re.MULTILINE)
    matches = list(pattern.finditer(wg_config))

    sections: list[tuple[str, str]] = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(wg_config)
        content = wg_config[start:end].strip("\n")
        sections.append((m.group("section"), content))

    interface_data: Dict[str, str] | None = None
    peer_sections: list[Dict[str, str]] = []

    for section_type, content in sections:
        if section_type.lower() == "interface":
            interface_data = parse_wg_section(content)
        elif section_type.lower() == "peer":
            peer_sections.append(parse_wg_section(content))

    if not interface_data:
        raise ValueError("No [Interface] section found in config")
    if "PrivateKey" not in interface_data:
        raise ValueError("Server [Interface] missing PrivateKey")
    if "Address" not in interface_data:
        raise ValueError("Server [Interface] missing Address")

    server_public_key = get_pubkey(interface_data["PrivateKey"])
    server_interface = build_wg_section(interface_data)
    server_as_peer = build_wg_section(
        {
            "PublicKey": server_public_key,
            "Endpoint": endpoint,
            "AllowedIPs": "0.0.0.0/0",
            "PersistentKeepalive": "25",
        }
    )

    server = {"name": "server", "interface_name": "wg0"}

    peers: list[dict[str, str | bool]] = []
    for i, peer_data in enumerate(peer_sections):
        if "PublicKey" not in peer_data:
            continue
        allowed_ips = peer_data["AllowedIPs"]
        peer_ip = allowed_ips.split(",")[0].strip()

        peer_interface_data: Dict[str, str] = {
            "Address": peer_ip,
            "PrivateKey": "UNKNOWN_PRIVATEKEY",
        }
        if "DNS" in interface_data:
            peer_interface_data["DNS"] = interface_data["DNS"]
        if "MTU" in interface_data:
            peer_interface_data["MTU"] = interface_data["MTU"]
        peer_interface = build_wg_section(peer_interface_data)
        peer_as_peer = build_wg_section(peer_data)
        peer_name = f"peer{i + 1}"
        peers.append({"name": peer_name, "interface": peer_interface, "as_peer": peer_as_peer, "enabled": True, "default": False})

    server_peer: dict[str, str | bool] = {"name": "server", "interface": server_interface, "as_peer": server_as_peer, "enabled": True, "default": True}
    peers.insert(0, server_peer)

    return {"server": server, "peers": peers}


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    wg_conf_path = sys.argv[1]
    endpoint = sys.argv[2]
    password = sys.argv[3] if len(sys.argv) > 3 else generate_random_password()

    try:
        with open(wg_conf_path, "r") as f:
            wg_config = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {wg_conf_path}", file=sys.stderr)
        sys.exit(1)

    parsed = parse_wg_conf(wg_config, endpoint)

    config: dict[str, Any] = {"basic": {"password": password, "bind_addr": "5000"}, "server": parsed["server"], "peers": parsed["peers"]}

    yaml_output = yaml.dump(config, default_flow_style=False, sort_keys=False)
    print(yaml_output)

    if len(sys.argv) <= 3:
        print(f"\n# Generated password: {password}", file=sys.stderr)
        print("# Save this password - you'll need it to log in!", file=sys.stderr)


if __name__ == "__main__":
    main()
