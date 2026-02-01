#!/usr/bin/env python3
"""Minimal sqlite -> wg-slim YAML converter for the provided demo DB.

This script is intentionally minimal and tailored to the demo database
and the expected YAML structure saved in `sqlite_conv_out.yaml`.
"""

import sys
import sqlite3
import secrets
from typing import Any
import yaml


def build_wg_section(values: dict[str, str]) -> str:
    lines: list[str] = []
    for k, v in values.items():
        if not v:
            continue
        lines.append(f"{k} = {v}")
    return "\n".join(lines)


def generate_random_password(length: int = 16) -> str:
    return secrets.token_urlsafe(length)[:length]


class _MultilineDumper(yaml.SafeDumper):
    pass


def _resolve_endpoint(cursor: sqlite3.Cursor, iface_name: str, default_port: Any) -> str:
    """Return a host:port endpoint for the given interface name from DB.

    Falls back to SERVER_IP and the provided default_port when missing.
    """
    row = cursor.execute("SELECT host,port FROM user_configs_table WHERE id = ?", (iface_name,)).fetchone()
    host = row["host"] if row and row["host"] else "SERVER_IP"
    port = row["port"] if row and row["port"] else default_port
    return f"{host}:{port}"


def _str_representer(dumper: Any, data: str) -> Any:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.add_representer(str, _str_representer, Dumper=_MultilineDumper)


def parse_sqlite_db(db_path: str, password_override: str | None = None) -> dict[str, Any]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Single enabled interface
    c.execute("SELECT * FROM interfaces_table WHERE enabled = 1 LIMIT 1")
    iface = c.fetchone()

    password = password_override
    if not password:
        c.execute("SELECT session_password FROM general_table WHERE id = 1")
        gr = c.fetchone()
        password = gr["session_password"] if gr and gr["session_password"] else generate_random_password()

    # Pull hooks (PostUp/PostDown) from hooks_table for this interface
    hooks = c.execute("SELECT * FROM hooks_table WHERE id = ?", (iface["name"],)).fetchone()
    post_up = hooks["post_up"] if hooks and hooks["post_up"] else ""
    post_down = hooks["post_down"] if hooks and hooks["post_down"] else ""

    # load user config defaults
    usercfg = c.execute("SELECT * FROM user_configs_table WHERE id = ?", (iface["name"],)).fetchone()
    default_dns = usercfg["default_dns"] if usercfg and usercfg["default_dns"] else ""

    server_interface = build_wg_section(
        {
            "PrivateKey": iface["private_key"],
            "Address": f"{iface['ipv4_cidr']}, {iface['ipv6_cidr']}",
            "ListenPort": str(iface["port"]),
            "MTU": str(iface["mtu"]),
            "PostUp": post_up,
            "PostDown": post_down,
        }
    )

    server_as_peer = build_wg_section(
        {
            "PublicKey": iface["public_key"],
            "Endpoint": _resolve_endpoint(c, iface["name"], iface["port"]),
            "AllowedIPs": "0.0.0.0/0, ::/0",
            "PersistentKeepalive": "25",
        }
    )

    server: dict[str, Any] = {"name": "server", "interface_name": iface["device"]}

    peers: list[dict[str, Any]] = []
    peers.append({"name": "server", "interface": server_interface, "as_peer": server_as_peer, "enabled": True, "default": True})

    c.execute("SELECT * FROM clients_table WHERE interface_id = ? ORDER BY id", (iface["name"],))
    for row in c.fetchall():
        ipv4 = row["ipv4_address"]
        ipv6 = row["ipv6_address"]

        # DNS in DB is stored as a simple array-like string; strip brackets/quotes
        dns = row["dns"] or default_dns or ""
        if dns.startswith("[") and dns.endswith("]"):
            inner = dns.strip()[1:-1]
            parts: list[str] = [p.strip().strip('"').strip("'") for p in inner.split(",") if p.strip()]
            dns = ", ".join(parts)

        peer_interface = build_wg_section(
            {
                "PrivateKey": row["private_key"],
                "Address": f"{ipv4}, {ipv6}",
                "DNS": dns,
                "MTU": str(row["mtu"]),
            }
        )

        # For this demo DB produce AllowedIPs as the client's own addresses with /32 and /128
        allowed_parts: list[str] = []
        if ipv4:
            allowed_parts.append(f"{ipv4}/32")
        if ipv6:
            allowed_parts.append(f"{ipv6}/128")
        allowed = ", ".join(allowed_parts)

        peer_as_peer = build_wg_section(
            {
                "PublicKey": row["public_key"],
                "AllowedIPs": allowed,
                "PresharedKey": row["pre_shared_key"] or "",
            }
        )

        peers.append(
            {
                "name": row["name"],
                "interface": peer_interface,
                "as_peer": peer_as_peer,
                "enabled": bool(row["enabled"]),
                "default": False,
            }
        )

    conn.close()
    return {"server": server, "peers": peers, "password": password}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    db_path = sys.argv[1]
    parsed = parse_sqlite_db(db_path)

    cfg: dict[str, Any] = {
        "basic": {"password": parsed["password"], "bind_addr": "5000"},
        "server": parsed["server"],
        "peers": parsed["peers"],
    }

    print(yaml.dump(cfg, default_flow_style=False, sort_keys=False, Dumper=_MultilineDumper))


if __name__ == "__main__":
    main()
