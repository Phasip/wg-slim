"""Typed models and a synced configuration manager for WireGuard."""

from __future__ import annotations

import logging
import os
import re
import threading
import sys
from ipaddress import ip_address, ip_network
from typing import Any, Callable, Optional

import pyqrcode
import io
import yaml
from yaml.nodes import Node
import wg_utils
from wg_manager import WgManager
from pydantic import ValidationError as PydanticValidationError

HERE = os.path.abspath(os.path.dirname(__file__))
GEN_SRC = os.path.join(HERE, "openapi_generated", "python-fastapi", "src")
if GEN_SRC not in sys.path:
    sys.path.insert(0, GEN_SRC)

# disable e402: module level import not at top of file
from openapi_server.models.config_basic import ConfigBasic  # noqa: E402
from openapi_server.models.server import Server  # noqa: E402
from openapi_server.models.peer import Peer  # noqa: E402
from openapi_server.models.wire_guard_config import WireGuardConfig  # noqa: E402

logger = logging.getLogger(__name__)


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    pass


class PeerNotFoundException(Exception):
    """Raised when a requested peer is not found in the configuration."""

    pass


class PeerExistsException(Exception):
    """Raised when attempting to add a peer that already exists in the configuration."""

    pass


class ConfigSyncException(Exception):
    """Raised when a config sync watcher fails."""

    pass


class DontKnowPeersPrivatekey(Exception):
    """Raised when a peer does not have a known private key in its interface block."""

    pass


class _MultilineStrDumper(yaml.SafeDumper):
    pass


def _str_representer(dumper: yaml.SafeDumper, data: str) -> Node:
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)  # type: ignore


_MultilineStrDumper.add_representer(str, _str_representer)


class ConfigHelper:
    """Helpers to operate on generated config models."""

    @staticmethod
    def set_interface_value(obj: Peer, key: str, value: str) -> None:
        values = wg_utils.parse_wg_section(obj.interface)
        values[key] = value
        obj.interface = wg_utils.build_wg_section(values)

    @staticmethod
    def set_as_peer_value(obj: Peer, key: str, value: str) -> None:
        values = wg_utils.parse_wg_section(obj.as_peer)
        values[key] = value
        obj.as_peer = wg_utils.build_wg_section(values)

    @staticmethod
    def to_yaml(obj: Any) -> str:
        return yaml.dump(obj.model_dump(), Dumper=_MultilineStrDumper, sort_keys=False)

    @staticmethod
    def update_from_yaml(obj: Any, yaml_content: str) -> None:
        data = yaml.safe_load(yaml_content)
        validated = obj.__class__.model_validate(data)
        for key, value in validated.model_dump().items():
            setattr(obj, key, value)


def get_peer(cfg: WireGuardConfig, name: str) -> Peer:
    """Return a peer object from a WireGuard config or raise PeerNotFoundException."""
    try:
        return next(p for p in cfg.peers if p.name == name)
    except StopIteration:
        raise PeerNotFoundException(f"Peer '{name}' not found") from None


class SyncedConfigManager:
    """Manages a WireGuard YAML config and keeps it synced to disk."""

    def __init__(self, file_path: str) -> None:
        self.file_path = os.path.abspath(file_path)
        self._on_config_change: list[Callable[[], None]] = []
        self._lock: threading.RLock = threading.RLock()
        self._load()

    @property
    def config(self) -> WireGuardConfig:
        return self._config

    def _load(self) -> None:
        with open(self.file_path) as f:
            data = yaml.safe_load(f)
        cfg = WireGuardConfig.model_validate(data)

        cfg.basic = ConfigBasic.model_validate(cfg.basic)
        cfg.server = Server.model_validate(cfg.server)
        cfg.peers = [Peer.model_validate(p) for p in cfg.peers]

        self._config = cfg
        logger.info("Loaded config from %s", self.file_path)

    def save(self) -> None:
        with self._lock:
            # Call watchers before writing to disk; short-circuit on first failure
            for watcher in self._on_config_change:
                try:
                    watcher()
                except ConfigSyncException:
                    # Reload the previous config from disk to restore valid state
                    self._load()
                    raise
            # Write the configuration only after all watchers succeed
            with open(self.file_path, "w") as f:
                yaml.dump(self._config.model_dump(), f, Dumper=_MultilineStrDumper, default_flow_style=False)
            logger.info("Saved config to %s", self.file_path)

    def add_on_config_change(self, callback: Callable[[], None]) -> None:
        """Register a callback invoked before the config is saved to disk.

        Callbacks are called in order. If any raises ConfigSyncException,
        the save is aborted and the previous config is reloaded from disk.
        """
        self._on_config_change.append(callback)

    def add_peer(self, name: str) -> Peer:
        with self._lock:
            if not re.match(r"^[a-zA-Z0-9_-]+$", name):
                raise ValueError("Invalid peer name")
            if any(p.name == name for p in self._config.peers):
                raise PeerExistsException(f"Peer '{name}' exists")
            srv = self._config.server
            # Server interface details are stored in the peer with name == server.name
            server_peer = get_peer(self._config, srv.name)
            server_addr = wg_utils.parse_wg_section(server_peer.interface)["Address"]
            network = ip_network(server_addr, strict=False)
            used = {ip_address(server_addr.split("/")[0])} | {ip_address(wg_utils.parse_wg_section(p.interface)["Address"].split("/")[0]) for p in self._config.peers}

            next_ip = next(h for h in network.hosts() if h not in used)

            priv, pub = WgManager.generate_keypair()

            interface_data = wg_utils.WireguardDict(
                {
                    "Address": f"{next_ip}/32",
                    "PrivateKey": priv,
                    "DNS": "1.1.1.1, 8.8.8.8",
                    "MTU": "1420",
                }
            )
            as_peer_data = wg_utils.WireguardDict(
                {
                    "PublicKey": pub,
                    "AllowedIPs": f"{next_ip}/32",
                    "PersistentKeepalive": "25",
                }
            )
            interface_str = wg_utils.build_wg_section(interface_data)
            as_peer_str = wg_utils.build_wg_section(as_peer_data)

            peer = Peer.model_validate({"name": name, "interface": interface_str, "as_peer": as_peer_str, "enabled": True})
            self._config.peers.append(peer)
            self.save()
            return peer

    def remove_peer(self, name: str) -> None:
        with self._lock:
            peer = get_peer(self._config, name)
            self._config.peers.remove(peer)
            self.save()

    def regenerate_key(self, entity_name: str) -> None:
        priv, pub = WgManager.generate_keypair()
        target = get_peer(self._config, entity_name)

        ConfigHelper.set_interface_value(target, "PrivateKey", priv)
        ConfigHelper.set_as_peer_value(target, "PublicKey", pub)
        self.save()

    def update_peer_from_yaml(self, peer_name: str, yaml_content: str) -> None:
        """Update a peer from YAML and save the configuration."""
        with self._lock:
            peer = get_peer(self._config, peer_name)

            ConfigHelper.update_from_yaml(peer, yaml_content)
            # If this peer is now marked default, clear the flag on others
            if peer.default:
                for p in self._config.peers:
                    p.default = p.name == peer.name
            self.save()

    def generate_server_config(self, server_peer_name: str) -> str:
        """Generate a simple server config string for the named server peer.

        Returns the config as a string; does not write to disk.
        """
        with self._lock:
            server_peer = get_peer(self._config, server_peer_name)
            server_peer_section = wg_utils.parse_wg_section(server_peer.as_peer)

            content = f"[Interface]\n{server_peer.interface}\n"
            for p in self._config.peers:
                if p.enabled and p.name != server_peer_name:
                    peer_dict = wg_utils.parse_wg_section(p.as_peer)
                    merged, conflict_comment = self._merge_presharedkey(peer_dict, peer_dict, server_peer_section)
                    content += f"\n[Peer]\n{wg_utils.build_wg_section(merged)}\n"
                    if conflict_comment:
                        content += f"# {conflict_comment}\n"
                        logging.warning("Conflicting PresharedKey when generating server config for %s: keeping client's value", p.name)
            return content

    def render_server_fw_rules(self) -> Optional[str]:
        """Render the server `fw_rules` template, substituting a small set of
        variables and returning the resulting nftables ruleset as a string.

        Supported template variables:
        - `{{AllowedIPs}}`: the server peer AllowedIPs value (first CIDR)
        - `{{interface_name}}`: the configured server interface name

        Returns `None` when no `fw_rules` template is configured.
        """
        with self._lock:
            # Use model_dump to avoid dynamic attribute access (forbidden by tests)
            fw = self._config.server.fw_rules
            logger.info("fw_rules raw value: %r", fw)
            if not fw:
                return None

            # Find the server peer and its as_peer section
            server_peer = get_peer(self._config, self._config.server.name)
            as_peer = wg_utils.parse_wg_section(server_peer.as_peer)
            allowed = as_peer.get("AllowedIPs", None)
            rendered = fw.replace("{{interface_name}}", self._config.server.interface_name)
            if allowed:
                rendered = rendered.replace("{{AllowedIPs}}", allowed)
            return rendered

    def get_peer_config_string(self, name: str) -> str:
        peer = get_peer(self._config, name)

        # Ensure we know this peer's private key before returning its config
        parsed_self = wg_utils.parse_wg_section(peer.interface)
        priv = parsed_self.get("PrivateKey")
        if not priv or priv == "UNKNOWN_PRIVATEKEY":
            raise DontKnowPeersPrivatekey(f"Peer '{name}' has unknown private key")
        # If the requested peer has an Endpoint, treat it as a server and
        # return the server-style config generated for that peer.
        requested_peer_aspeer = wg_utils.parse_wg_section(peer.as_peer)
        if "Endpoint" in requested_peer_aspeer:
            return self.generate_server_config(peer.name)

        peers_with_endpoint: list[str] = []
        for p in self._config.peers:
            if p.name == name:
                continue
            parsed = wg_utils.parse_wg_section(p.as_peer)
            if "Endpoint" in parsed:
                peers_with_endpoint.append(p.as_peer)

        content = "[Interface]\n" + peer.interface + "\n\n"

        for as_peer in peers_with_endpoint:
            endpoint_peer_dict = wg_utils.parse_wg_section(as_peer)
            merged, conflict_comment = self._merge_presharedkey(endpoint_peer_dict, requested_peer_aspeer, endpoint_peer_dict)
            if conflict_comment:
                logger.warning(
                    "Conflicting PresharedKey when generating config for %s: keeping client's value",
                    name,
                )
            content += "[Peer]\n" + wg_utils.build_wg_section(merged) + "\n"
            if conflict_comment:
                content += f"# {conflict_comment}\n"
            content += "\n"
        return content

    def _merge_presharedkey(self, base_dict: wg_utils.WireguardDict, primary: wg_utils.WireguardDict, secondary: wg_utils.WireguardDict) -> tuple[wg_utils.WireguardDict, str | None]:
        """Merge PresharedKey selecting from primary/secondary while using
        `base_dict` for all other values.

        - `base_dict` provides the base values for the returned dict.
        - `primary` and `secondary` are only consulted for the PSK decision.
        - If `secondary` provides a PSK, it is preferred. If both provide PSKs
          and they differ, the primary PSK is returned as an alternate comment.
        - If only `primary` provides a PSK, it will be used.
        - Returns (merged_dict, conflict_comment_or_None).
        """
        merged = base_dict.copy()
        if "PresharedKey" in merged:
            del merged["PresharedKey"]
        psk_primary = primary.get("PresharedKey")
        psk_secondary = secondary.get("PresharedKey")
        comment = None
        if psk_primary:
            merged["PresharedKey"] = psk_primary
        elif psk_secondary:
            merged["PresharedKey"] = psk_secondary

        if psk_primary and psk_secondary and psk_primary != psk_secondary:
            comment = f"Alternate-PresharedKey: {psk_secondary}"

        return merged, comment

    def generate_peer_qrcode(self, name: str) -> bytes:
        buf = io.BytesIO()
        pyqrcode.create(self.get_peer_config_string(name)).png(buf, scale=6)  # type: ignore
        return buf.getvalue()

    def get_log_file_path(self) -> str:
        """Return the path to the logfile located next to the config file.

        The logfile is named `logs.log` and lives in the same directory as
        `self.file_path`.
        """
        base_dir = os.path.dirname(self.file_path)
        return os.path.join(base_dir, "logs.log")

    def get_raw_config(self, censor_password: bool = False) -> str:
        data = self._config.model_dump()
        if censor_password:
            data["basic"]["password"] = "PASSWORD_NOT_CHANGEABLE_IN_CONF_EDITOR"
        return yaml.dump(data, Dumper=_MultilineStrDumper, sort_keys=False)

    def set_raw_config(self, content: str, ignore_password: bool = False) -> None:
        with self._lock:
            try:
                data = yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise ConfigValidationError(f"Invalid YAML: {e}") from e
            old = self._config
            try:
                if ignore_password:
                    data["basic"]["password"] = self._config.basic.password

                cfg = WireGuardConfig.model_validate(data)

                # Ensure nested fields are validated to generated model types
                cfg.basic = ConfigBasic.model_validate(cfg.basic)
                cfg.server = Server.model_validate(cfg.server)
                cfg.peers = [Peer.model_validate(p) for p in cfg.peers]

                # Ensure that a peer matching server.name exists
                try:
                    _ = next(p for p in cfg.peers if p.name == cfg.server.name)
                except StopIteration:
                    raise ConfigValidationError(f"Server name '{cfg.server.name}' must match an existing peer") from None

                # Persist the new validated config; no per-object callbacks
                self._config = cfg
                self.save()
            except (PydanticValidationError, ValueError):
                self._config = old
                raise

    def set_peers(self, new_peers: list[Peer]) -> None:
        with self._lock:
            self._config.peers = new_peers
            self.save()

    def apply_template_to_peers(self, template_name: str) -> None:
        """Apply the `as_peer` WireGuard section from the named template peer
        to all other peers (excluding the template itself and the server
        peer). The PublicKey field is never overwritten.

        This method mutates the in-memory config and persists it via
        `save()` while holding the internal lock.
        """

        with self._lock:
            template_peer = get_peer(self._config, template_name)
            tpl = wg_utils.parse_wg_section(template_peer.as_peer)

            for p in self._config.peers:
                # Skip the template itself and the server peer
                if p.name == template_name or p.name == self._config.server.name:
                    continue
                dst = wg_utils.parse_wg_section(p.as_peer)
                for k, v in tpl.items():
                    if k == "PublicKey":
                        continue
                    dst[k] = v
                p.as_peer = wg_utils.build_wg_section(dst)

            self.save()

    @staticmethod
    def load_or_create(file_path: str, fallback_config_data: str) -> "SyncedConfigManager":
        """Load config from file_path, or create it using fallback_config_data if missing.

        If the file exists but is unreadable, this raises an error (unrecoverable).
        If the file does not exist, parse fallback_config_data, ensure a server peer
        exists, and write the config to file_path.
        """
        file_path = os.path.abspath(file_path)

        if os.path.exists(file_path):
            return SyncedConfigManager(file_path=file_path)

        # File missing: parse fallback and ensure server peer exists
        data = yaml.safe_load(fallback_config_data)

        if "password" not in data["basic"]:
            generated_password = wg_utils.generate_random_password()
            data["basic"]["password"] = generated_password
            print("First setup, no initial password provided.")
            print(f"Web management password: {generated_password}")
        assert "server" in data, "Fallback config missing 'server' section"
        if "name" not in data["server"]:
            data["server"]["name"] = "server"
            assert "peers" not in data, "Fallback config has 'peers' but no server.name. Must have server.name, or remove peers section."

        server_name = data["server"]["name"]
        if "peers" not in data:
            data["peers"] = []

        # Check if server peer exists
        server_peer_exists = any(p.get("name") == server_name for p in data["peers"])

        if not server_peer_exists:
            # Generate a new server peer
            priv, pub = WgManager.generate_keypair()

            interface_data = wg_utils.WireguardDict(
                {
                    "Address": "10.0.0.1/24",
                    "ListenPort": "51820",
                    "PrivateKey": priv,
                    "DNS": "1.1.1.1, 8.8.8.8",
                    "MTU": "1420",
                }
            )
            as_peer_data = wg_utils.WireguardDict(
                {
                    "PublicKey": pub,
                    "Endpoint": "server.example.com:51820",
                    "AllowedIPs": "0.0.0.0/0",
                    "PersistentKeepalive": "25",
                }
            )
            interface = wg_utils.build_wg_section(interface_data)
            as_peer = wg_utils.build_wg_section(as_peer_data)

            server_peer: dict[str, str | bool] = {
                "name": server_name,
                "interface": interface,
                "as_peer": as_peer,
                "enabled": True,
                "default": True,
            }
            data["peers"].append(server_peer)

        # Write the config file
        os.makedirs(os.path.dirname(file_path) or ".", exist_ok=True)
        fd = os.open(file_path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.dump(data, f, Dumper=_MultilineStrDumper, default_flow_style=False, sort_keys=False)

        return SyncedConfigManager(file_path=file_path)


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

    interface_data: Optional[wg_utils.WireguardDict] = None
    peer_sections: list[wg_utils.WireguardDict] = []

    for section_type, content in sections:
        if section_type.lower() == "interface":
            interface_data = wg_utils.parse_wg_section(content)
        elif section_type.lower() == "peer":
            peer_sections.append(wg_utils.parse_wg_section(content))

    if not interface_data:
        raise ConfigValidationError("No [Interface] section found in config")
    if "PrivateKey" not in interface_data:
        raise ConfigValidationError("Server [Interface] missing PrivateKey")
    if "Address" not in interface_data:
        raise ConfigValidationError("Server [Interface] missing Address")

    server_public_key = WgManager.get_pubkey(interface_data["PrivateKey"])
    server_interface = wg_utils.build_wg_section(interface_data)
    server_as_peer = wg_utils.build_wg_section(
        wg_utils.WireguardDict(
            {
                "PublicKey": server_public_key,
                "Endpoint": endpoint,
                "AllowedIPs": "0.0.0.0/0",
                "PersistentKeepalive": "25",
            }
        )
    )

    server = {"name": "server", "interface_name": "wg0"}

    peers: list[dict[str, str | bool]] = []
    for i, peer_data in enumerate(peer_sections):
        if "PublicKey" not in peer_data:
            continue
        allowed_ips = peer_data["AllowedIPs"]
        peer_ip = allowed_ips.split(",")[0].strip()

        peer_interface_data: wg_utils.WireguardDict = wg_utils.WireguardDict(
            {
                "Address": peer_ip,
                "PrivateKey": "UNKNOWN_PRIVATEKEY",
            }
        )
        if "DNS" in interface_data:
            peer_interface_data["DNS"] = interface_data["DNS"]
        if "MTU" in interface_data:
            peer_interface_data["MTU"] = interface_data["MTU"]
        peer_interface = wg_utils.build_wg_section(peer_interface_data)
        peer_as_peer = wg_utils.build_wg_section(peer_data)
        peer_name = f"peer{i + 1}"
        peers.append({"name": peer_name, "interface": peer_interface, "as_peer": peer_as_peer, "enabled": True, "default": False})

    # Insert the server as the first peer entry; this peer holds the server's interface and as_peer strings
    server_peer: dict[str, str | bool] = {"name": "server", "interface": server_interface, "as_peer": server_as_peer, "enabled": True, "default": True}
    peers.insert(0, server_peer)

    return {"server": server, "peers": peers}
