#!/usr/bin/env python3
"""Command-line utility for wg-slim API interactions."""

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import yaml
import wg_utils
import wgslim_api_client
from wgslim_api_client.models.login_request import LoginRequest
from wgslim_api_client.models.peers_post_request import PeersPostRequest


def load_config(config_file: str) -> Any:
    """Load configuration from YAML file."""
    config_path = Path(config_file)
    if not config_path.exists():
        print(f"Error: Config file not found: {config_file}", file=sys.stderr)
        sys.exit(1)

    with open(config_path) as f:
        config = yaml.safe_load(f)

    return config


def get_api_client(
    host: Optional[str] = None,
    port: Optional[int] = None,
    password: Optional[str] = None,
    config_file: Optional[str] = None,
) -> wgslim_api_client.DefaultApi:
    """Create and configure API client with authentication."""
    if config_file is None:
        config_file = os.environ.get("CONFIG_FILE", "/data/config.yaml")

    config = load_config(config_file)

    bind_host, bind_port = wg_utils.parse_bind_addr(str(config.get("basic", {}).get("bind_addr", "5000")))
    if host is None:
        host = wg_utils.local_url_host(bind_host)
    elif ":" in host and not host.startswith("["):
        host = f"[{host}]"

    if port is None:
        port = bind_port

    if password is None:
        password = config.get("basic", {}).get("password")
        if not password:
            print("Error: No password found in config (with basic.password_hash, pass --password)", file=sys.stderr)
            sys.exit(1)

    base_url = f"http://{host}:{port}/api"

    configuration = wgslim_api_client.Configuration(host=base_url)
    api_client = wgslim_api_client.ApiClient(configuration)
    api = wgslim_api_client.DefaultApi(api_client)

    login_response = api.login_post(LoginRequest(password=password))
    access_token = login_response.access_token

    configuration.access_token = access_token

    return api


def cmd_get_config(args: argparse.Namespace) -> None:
    """Get the raw YAML configuration."""
    api = get_api_client(
        host=args.host,
        port=args.port,
        password=args.password,
        config_file=args.config_file,
    )

    response = api.config_get()
    print(response.config)


def cmd_add_peer(args: argparse.Namespace) -> None:
    """Add a new peer."""
    api = get_api_client(
        host=args.host,
        port=args.port,
        password=args.password,
        config_file=args.config_file,
    )

    peer_request = PeersPostRequest(name=args.name)
    api.peers_post(peer_request)
    print(f"Peer '{args.name}' added successfully")


def cmd_list_peers(args: argparse.Namespace) -> None:
    """List all peers."""
    api = get_api_client(
        host=args.host,
        port=args.port,
        password=args.password,
        config_file=args.config_file,
    )

    response = api.peers_get()
    peers = response.peers if response.peers else []

    if args.json:
        # Convert pydantic models to dicts for JSON serialization
        peers_data = [p.dict() for p in peers]
        print(json.dumps(peers_data, indent=2, default=str))
    else:
        if not peers:
            print("No peers configured")
        else:
            print(f"{'Name':<20} {'Enabled':<10}")
            print("-" * 30)
            for peer in peers:
                name = peer.name if peer.name else ""
                enabled = "Yes" if peer.enabled else "No"
                print(f"{name:<20} {enabled:<10}")


def cmd_get_peer_config(args: argparse.Namespace) -> None:
    """Get configuration for a specific peer."""
    api = get_api_client(
        host=args.host,
        port=args.port,
        password=args.password,
        config_file=args.config_file,
    )

    response = api.peers_peer_name_config_get(args.name)
    print(response.config)


def cmd_delete_peer(args: argparse.Namespace) -> None:
    """Delete a peer."""
    api = get_api_client(
        host=args.host,
        port=args.port,
        password=args.password,
        config_file=args.config_file,
    )

    api.peers_peer_name_delete(args.name)
    print(f"Peer '{args.name}' deleted successfully")


def cmd_hash_password(args: argparse.Namespace) -> None:
    """Print a basic.password_hash value for a password read from the terminal or stdin."""
    if sys.stdin.isatty():
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            print("Error: Passwords do not match", file=sys.stderr)
            sys.exit(1)
    else:
        password = sys.stdin.readline().rstrip("\n")
    if not password:
        print("Error: Empty password", file=sys.stderr)
        sys.exit(1)
    print(wg_utils.hash_password(password))


def main() -> None:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(description="wg-slim CLI tool for managing WireGuard configurations")

    parser.add_argument(
        "--host",
        help="API host (default: localhost)",
        default=None,
    )
    parser.add_argument(
        "--port",
        type=int,
        help="API port (default: from config file)",
        default=None,
    )
    parser.add_argument(
        "--password",
        help="API password (default: from config file)",
        default=None,
    )
    parser.add_argument(
        "--config-file",
        help="Path to config file (default: $CONFIG_FILE or /data/config.yaml)",
        default=None,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    subparsers.add_parser("get-config", help="Get the raw YAML configuration")

    parser_add = subparsers.add_parser("add-peer", help="Add a new peer")
    parser_add.add_argument("name", help="Peer name")

    parser_list = subparsers.add_parser("list-peers", help="List all peers")
    parser_list.add_argument("--json", action="store_true", help="Output in JSON format")

    parser_get_peer = subparsers.add_parser("get-peer-config", help="Get configuration for a specific peer")
    parser_get_peer.add_argument("name", help="Peer name")

    parser_delete = subparsers.add_parser("delete-peer", help="Delete a peer")
    parser_delete.add_argument("name", help="Peer name")

    subparsers.add_parser("hash-password", help="Print a basic.password_hash value (reads the password from the terminal or stdin)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    command_map = {
        "get-config": cmd_get_config,
        "add-peer": cmd_add_peer,
        "list-peers": cmd_list_peers,
        "get-peer-config": cmd_get_peer_config,
        "delete-peer": cmd_delete_peer,
        "hash-password": cmd_hash_password,
    }

    command_map[args.command](args)


if __name__ == "__main__":
    main()
