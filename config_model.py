"""Typed models and a synced configuration manager for WireGuard."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import threading
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Any, Callable, Optional

import yaml
from yaml.nodes import Node
import wg_utils
from wg_manager import WgManager
from pydantic import ValidationError as PydanticValidationError

# `openapi_server` is generated from openapi.yaml into openapi_generated/ and
# installed by `make install-generated` (run for you by `make test`).
from openapi_server.models.peer import Peer
from openapi_server.models.server import Server
from openapi_server.models.wire_guard_config import WireGuardConfig

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


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that refuses YAML aliases.

    Aliases let a tiny document expand into an enormous object graph (an
    "alias bomb"), so they are rejected outright for YAML that arrives through
    the API. Configs written by wg-slim itself never contain aliases.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ConfigValidationError("YAML aliases are not supported")
        return super().compose_node(parent, index)


def load_untrusted_yaml(content: str) -> Any:
    """Parse YAML received through the API, refusing aliases.

    Raises ConfigValidationError (mapped to HTTP 400) on anything unparseable.
    """
    try:
        return yaml.load(content, Loader=_NoAliasSafeLoader)
    except yaml.YAMLError as e:
        raise ConfigValidationError(f"Invalid YAML: {e}") from e


def _require_mapping(value: Any, message: str) -> None:
    """Raise ConfigValidationError unless `value` is a mapping.

    YAML from the API can be any node type, so indexing it blindly turns a bad
    request into an unhandled KeyError/TypeError (HTTP 500).
    """
    if type(value) is not dict:
        raise ConfigValidationError(message)


def _peer_ip_addresses(peer: Peer) -> set[IPv4Address | IPv6Address]:
    """Return every IP address in a peer's interface `Address` value.

    Unparseable or missing entries are skipped: a single malformed peer must
    not break address allocation for the whole config.
    """
    raw = wg_utils.parse_wg_section(peer.interface).get("Address")
    found: set[IPv4Address | IPv6Address] = set()
    if not raw:
        return found
    for entry in raw.split(","):
        candidate = entry.split("/")[0].strip()
        if not candidate:
            continue
        try:
            found.add(ip_address(candidate))
        except ValueError:
            logger.warning("Ignoring unparseable Address %r on peer %s", candidate, peer.name)
    return found


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
        data = load_untrusted_yaml(yaml_content)
        validated = obj.__class__.model_validate(data)
        for key, value in validated.model_dump().items():
            setattr(obj, key, value)


# `as_peer` keys that identify a single peer and so are never copied by
# `apply_template_to_peers`. Lowercase, matching `WireguardDict` storage.
TEMPLATE_SKIP_KEYS = {"publickey", "allowedips"}


def get_peer(cfg: WireGuardConfig, name: str) -> Peer:
    """Return a peer object from a WireGuard config or raise PeerNotFoundException."""
    try:
        return next(p for p in cfg.peers if p.name == name)
    except StopIteration:
        raise PeerNotFoundException(f"Peer '{name}' not found") from None


# [Interface] values for new peers when the `default` peer doesn't set them.
NEW_PEER_INTERFACE_DEFAULTS = {"DNS": "1.1.1.1, 8.8.8.8", "MTU": "1420"}

# `basic` holds exactly one of these; see `_validate_password_settings`.
PASSWORD_FIELDS = ("password", "password_hash")


class SyncedConfigManager:
    """Manages a WireGuard YAML config and keeps it synced to disk."""

    def __init__(self, file_path: str) -> None:
        self.file_path = os.path.abspath(file_path)
        self._on_config_change: list[Callable[[], None]] = []
        self._lock: threading.RLock = threading.RLock()
        self._load()

    @property
    def config(self) -> WireGuardConfig:
        """The live config. Only read or change it while holding the lock
        (inside this class, or in a watcher, which runs under it); use
        `snapshot()` elsewhere."""
        return self._config

    def snapshot(self) -> WireGuardConfig:
        """Return a deep copy of the config, safe to read without the lock."""
        with self._lock:
            return self._config.model_copy(deep=True)

    def _load(self) -> None:
        with open(self.file_path) as f:
            data = yaml.safe_load(f)
        # WireGuardConfig declares `basic`/`server`/`peers` as model types, so
        # pydantic validates the nested sections as part of this call.
        self._config = WireGuardConfig.model_validate(data)
        self._validate_password_settings()
        logger.info("Loaded config from %s", self.file_path)

    def _validate_password_settings(self) -> None:
        basic = self._config.basic
        if basic.password is not None and basic.password_hash is not None:
            raise ConfigValidationError("Set either basic.password or basic.password_hash, not both")
        if basic.password is None and basic.password_hash is None:
            raise ConfigValidationError("One of basic.password or basic.password_hash must be set")
        if basic.password_hash is not None:
            try:
                wg_utils.validate_password_hash(basic.password_hash)
            except ValueError as e:
                raise ConfigValidationError(str(e)) from None

    def check_password(self, password: str) -> bool:
        """Check a login password against basic.password or basic.password_hash."""
        basic = self._config.basic
        if basic.password_hash is not None:
            return wg_utils.verify_password(password, basic.password_hash)
        assert basic.password is not None, "config validation guarantees a password"
        return wg_utils.secure_strcmp(password, basic.password)

    def set_password(self, password: str) -> None:
        """Change the web password, keeping whichever form (plain or hashed) is configured."""
        with self._lock:
            basic = self._config.basic
            if basic.password_hash is not None:
                basic.password_hash = wg_utils.hash_password(password)
            else:
                basic.password = password
            self.save()

    def _validate_invariants(self) -> None:
        """Check the structural rules the rest of the code relies on.

        Callers mutate the in-memory config and then call `save()`, so this
        runs there rather than in each caller.
        """
        self._validate_password_settings()
        names = [p.name for p in self._config.peers]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ConfigValidationError(f"Duplicate peer name(s): {', '.join(duplicates)}")
        if self._config.server.name not in names:
            raise ConfigValidationError(f"Server name '{self._config.server.name}' must match an existing peer")
        # Checked here so a malformed section is a validation error, not a
        # crash while generating the WireGuard config.
        for p in self._config.peers:
            for section_name, section in (("interface", p.interface), ("as_peer", p.as_peer)):
                try:
                    wg_utils.parse_wg_section(section)
                except wg_utils.WgSectionSyntaxError as e:
                    raise ConfigValidationError(f"Peer '{p.name}' {section_name}: {e}") from None

    def _write_to_disk(self) -> None:
        """Write the config atomically, so an interrupted save cannot destroy it.

        The config holds every private key, so the replacement file is created
        0600 and swapped in with `os.replace()`.
        """
        directory = os.path.dirname(self.file_path) or "."
        fd, tmp_path = tempfile.mkstemp(prefix=".config-", suffix=".yaml.tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                yaml.dump(self._dump(), f, Dumper=_MultilineStrDumper, default_flow_style=False)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.file_path)
        except OSError:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def save(self) -> None:
        with self._lock:
            # Any failure below - validation, a watcher, or the write itself -
            # leaves the in-memory config half-changed, so reload the last good
            # config from disk before the exception propagates.
            completed = False
            watchers_run = 0
            try:
                self._validate_invariants()
                # Call watchers before writing to disk; short-circuit on first failure
                for watcher in self._on_config_change:
                    # Counted before the call: a failing watcher may have
                    # applied part of the change before it raised.
                    watchers_run += 1
                    watcher()
                # Write the configuration only after all watchers succeed
                self._write_to_disk()
                completed = True
            finally:
                if not completed:
                    self._load()
                    self._reapply(self._on_config_change[:watchers_run])
            logger.info("Saved config to %s", self.file_path)

    def _reapply(self, watchers: list[Callable[[], None]]) -> None:
        """Re-run watchers against the reloaded config after a failed save.

        Watchers change live state (the WireGuard interface, the firewall), so
        when a later step fails, the ones that already ran would otherwise
        leave the system running a config that was never saved. Runs inside a
        `finally`, so failures are logged rather than raised: raising would
        hide the error that aborted the save.
        """
        for watcher in watchers:
            try:
                watcher()
            except ConfigSyncException as e:
                logger.error("Could not restore the previous config after a failed save: %s", e)

    def add_on_config_change(self, callback: Callable[[], None]) -> None:
        """Register a callback invoked before the config is saved to disk.

        Callbacks are called in order. If any raises ConfigSyncException,
        the save is aborted, the previous config is reloaded from disk and the
        callbacks that already ran are called again to re-apply it.
        """
        self._on_config_change.append(callback)

    def add_peer(self, name: str) -> Peer:
        with self._lock:
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
                raise ConfigValidationError("Invalid peer name")
            if any(p.name == name for p in self._config.peers):
                raise PeerExistsException(f"Peer '{name}' exists")
            srv = self._config.server
            # Server interface details are stored in the peer with name == server.name
            server_peer = get_peer(self._config, srv.name)
            server_addr_raw = wg_utils.parse_wg_section(server_peer.interface).get("Address")
            if not server_addr_raw:
                raise ConfigValidationError(f"Server peer '{srv.name}' has no Address in its interface section")

            # A dual-stack server lists several addresses; allocate from the first.
            server_addr = server_addr_raw.split(",")[0].strip()
            try:
                network = ip_network(server_addr, strict=False)
            except ValueError as e:
                raise ConfigValidationError(f"Server peer '{srv.name}' has an invalid Address {server_addr!r}: {e}") from None

            used: set[IPv4Address | IPv6Address] = set()
            for p in self._config.peers:
                used |= _peer_ip_addresses(p)

            next_ip = next((h for h in network.hosts() if h not in used), None)
            if next_ip is None:
                raise ConfigValidationError(f"No free addresses left in {network}")

            priv, pub = WgManager.generate_keypair()

            interface_data = wg_utils.WireguardDict(
                {
                    "Address": f"{next_ip}/32",
                    "PrivateKey": priv,
                    **self._new_peer_interface_defaults(),
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

    def _new_peer_interface_defaults(self) -> dict[str, str]:
        """DNS and MTU for a new peer: taken from the peer marked `default`,
        falling back to NEW_PEER_INTERFACE_DEFAULTS for keys it doesn't set."""
        values = dict(NEW_PEER_INTERFACE_DEFAULTS)
        template = next((p for p in self._config.peers if p.default), None)
        if template is not None:
            section = wg_utils.parse_wg_section(template.interface)
            for key in values:
                value = section.get(key)
                if value:
                    values[key] = value
        return values

    def remove_peer(self, name: str) -> None:
        with self._lock:
            peer = get_peer(self._config, name)
            self._config.peers.remove(peer)
            self.save()

    def regenerate_key(self, entity_name: str) -> None:
        with self._lock:
            target = get_peer(self._config, entity_name)
            priv, pub = WgManager.generate_keypair()

            ConfigHelper.set_interface_value(target, "PrivateKey", priv)
            ConfigHelper.set_as_peer_value(target, "PublicKey", pub)
            self.save()

    def set_peer_enabled(self, peer_name: str, enabled: bool) -> None:
        with self._lock:
            get_peer(self._config, peer_name).enabled = enabled
            self.save()

    def get_peer_yaml(self, peer_name: str) -> str:
        with self._lock:
            return ConfigHelper.to_yaml(get_peer(self._config, peer_name))

    def import_wg_config(self, wg_config: str, endpoint: str) -> None:
        """Replace the server and peers with those parsed from a wg-quick config.

        Only allowed while the server peer is the only peer, so an import can
        never silently drop existing peers.
        """
        with self._lock:
            if len(self._config.peers) != 1:
                raise ConfigValidationError("Importing WireGuard configs is only supported when no peers exist except the server peer")
            parsed = parse_wg_conf(wg_config, endpoint)
            self._config.server = Server.model_validate(parsed["server"])
            self._config.peers = [Peer.model_validate(p) for p in parsed["peers"]]
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

    def update_server_from_yaml(self, yaml_content: str) -> None:
        """Update the server's own peer from YAML and save the configuration."""
        with self._lock:
            self.update_peer_from_yaml(self._config.server.name, yaml_content)

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
        with self._lock:
            return self._peer_config_string(name)

    def _peer_config_string(self, name: str) -> str:
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
        - If `primary` provides a PSK, it is used. If only `secondary` provides
          a PSK, it will be used as fallback.
        - If both differ, `secondary` is noted as an alternate in a comment.
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

    def _dump(self) -> dict[str, Any]:
        """Return the config as plain data, leaving out the unused password field."""
        data = self._config.model_dump()
        for field in PASSWORD_FIELDS:
            if data["basic"][field] is None:
                del data["basic"][field]
        return data

    def get_raw_config(self, censor_password: bool = False) -> str:
        with self._lock:
            data = self._dump()
        if censor_password:
            # Only the configured field is shown, so the editor keeps
            # displaying which form is in use.
            data["basic"] = {k: ("PASSWORD_NOT_CHANGEABLE_IN_CONF_EDITOR" if k in PASSWORD_FIELDS else v) for k, v in data["basic"].items()}
        return yaml.dump(data, Dumper=_MultilineStrDumper, sort_keys=False)

    def set_raw_config(self, content: str, ignore_password: bool = False) -> None:
        with self._lock:
            data = load_untrusted_yaml(content)
            _require_mapping(data, "Config must be a YAML mapping with 'basic', 'server' and 'peers' sections")
            old = self._config
            try:
                if ignore_password:
                    basic = data.get("basic")
                    _require_mapping(basic, "Config is missing a 'basic' section")
                    for field in PASSWORD_FIELDS:
                        basic.pop(field, None)
                    basic.update({k: v for k, v in self._dump()["basic"].items() if k in PASSWORD_FIELDS})

                # Persist the new config; `save()` enforces the structural
                # invariants (unique peer names, a peer named after the server)
                # and reloads the last good config if anything rejects it.
                self._config = WireGuardConfig.model_validate(data)
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
        peer). Per-peer identity (`TEMPLATE_SKIP_KEYS`) is never overwritten:
        copying AllowedIPs would give every peer the template's address, and
        WireGuard routes an address to only one peer.

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
                    if k.lower() in TEMPLATE_SKIP_KEYS:
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

        if "password" not in data["basic"] and "password_hash" not in data["basic"]:
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

    try:
        server_public_key = WgManager.get_pubkey(interface_data["PrivateKey"])
    except subprocess.CalledProcessError:
        raise ConfigValidationError("Server [Interface] has an invalid PrivateKey") from None
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
        allowed_ips = peer_data.get("AllowedIPs")
        if not allowed_ips:
            raise ConfigValidationError(f"[Peer] {peer_data['PublicKey']} has no AllowedIPs")
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
