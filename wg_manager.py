"""WireGuard manager for interface and peer statistics and config sync."""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import tempfile

logger = logging.getLogger(__name__)


@dataclass
class PeerStats:
    public_key: str
    endpoint: Optional[str] = None
    allowed_ips: list[str] = field(default_factory=list[str])
    latest_handshake: Optional[datetime] = None
    transfer_rx: int = 0
    transfer_tx: int = 0
    persistent_keepalive: Optional[int] = None


@dataclass
class InterfaceStats:
    name: str
    private_key: str
    public_key: str
    listening_port: int
    peers: list[PeerStats] = field(default_factory=list[PeerStats])

    @property
    def peer_count(self) -> int:
        return len(self.peers)


class WgManager:
    @classmethod
    def _run_command(cls, args: list[str], input: Optional[str] = None, check: bool = True) -> tuple[int, str, str]:
        """Run a subprocess command and return the CompletedProcess or raise CalledProcessError.

        Accepts optional `input` to pass to the subprocess stdin.
        """
        try:
            ret = subprocess.run(
                args,
                text=True,
                capture_output=True,
                check=check,
                input=input,
            )
            return (ret.returncode, ret.stdout, ret.stderr)
        except subprocess.CalledProcessError as e:
            # Log command, return code, stdout and stderr then re-raise
            logger.error(f"WgManager subprocess failed: cmd={e.cmd} returncode={e.returncode}")
            for line in e.stdout.splitlines():
                logger.error(f"  stdout: {line}")
            for line in e.stderr.splitlines():
                logger.error(f"  stderr: {line}")
            raise

        except FileNotFoundError as e:
            logger.error(
                "WgManager subprocess failed: cmd=%s error=%s",
                args,
                e,
            )
            raise

    @classmethod
    def is_interface_up(cls, interface: str) -> bool:
        (returncode, _, _) = cls._run_command(["ip", "link", "show", "dev", interface], check=False)
        return returncode == 0

    @classmethod
    def get_interface_stats(cls, interface: str) -> InterfaceStats:
        """Parse `wg show <interface> dump` output and return InterfaceStats.

        Assumes the standard dump format.
        """
        (_, stdout, _) = cls._run_command(["wg", "show", interface, "dump"])
        lines = stdout.strip().splitlines()

        if not lines:
            raise ValueError(f"No data returned for interface {interface}")

        hdr = lines[0].split("\t")
        iface = InterfaceStats(
            name=interface,
            private_key=hdr[0],
            public_key=hdr[1],
            listening_port=int(hdr[2]),
        )

        for line in lines[1:]:
            public_key, _, endpoint, allowed, latest_ts, rx, tx, pka = line.split("\t")[:8]

            latest_handshake = datetime.fromtimestamp(int(latest_ts)) if latest_ts != "0" else None
            allowed_ips = [] if allowed == "(none)" else allowed.split(",")
            persistent_keepalive = None if pka == "off" else int(pka)

            iface.peers.append(
                PeerStats(
                    public_key=public_key,
                    endpoint=None if endpoint == "(none)" else endpoint,
                    allowed_ips=allowed_ips,
                    latest_handshake=latest_handshake,
                    transfer_rx=int(rx),
                    transfer_tx=int(tx),
                    persistent_keepalive=persistent_keepalive,
                )
            )

        return iface

    @classmethod
    def bring_up(cls, config_file: str) -> None:
        """Bring the interface up using wg-quick. Accepts config_file path."""
        cls._run_command(["wg-quick", "up", config_file], check=True)

    @classmethod
    def bring_down(cls, config_file: str) -> None:
        """Bring the interface down using wg-quick. Accepts config_file path."""
        # Do not raise on failure here; best-effort teardown.
        cls._run_command(["wg-quick", "down", config_file], check=False)

    @classmethod
    def sync_config(cls, interface: str, config_file: str) -> None:
        """Apply the stripped config file to the interface using wg syncconf via a temporary file."""
        (returncode, output, stderr) = cls._run_command(["wg-quick", "strip", config_file])
        # Write the stripped config to a temporary file and pass its path to wg syncconf.
        with tempfile.NamedTemporaryFile(prefix="wg_conf_", mode="w", delete=True) as tf:
            tf.write(output)
            tf.flush()
            cls._run_command(["wg", "syncconf", interface, tf.name])

    @classmethod
    def get_wg_show_peer_blocks(cls, interface: str) -> dict[str, str]:
        """Run `wg show <interface>` and return a mapping of peer public_key -> raw text block.

        This intentionally does not parse the values; it only splits the raw output
        into sections for each peer so the UI can display the original text.
        """
        (_, stdout, _) = cls._run_command(["wg", "show", interface])

        blocks: dict[str, list[str]] = {}
        current_block: list[str] = []
        current_key: Optional[str] = None

        for line in stdout.splitlines():
            if line.startswith("peer:"):
                _, peer_key = line.split()
                current_key = peer_key
                current_block = [line]
                blocks[peer_key] = current_block
            elif current_key is not None:
                current_block.append(line)

        return {k: "\n".join(v) for k, v in blocks.items()}

    @classmethod
    def get_pubkey(cls, private_key: str) -> str:
        """Derive the public key from a WireGuard private key using `wg pubkey`."""
        (returncode, stdout, stderr) = cls._run_command(["wg", "pubkey"], input=private_key)
        return stdout.strip()

    @classmethod
    def generate_keypair(cls) -> tuple[str, str]:
        """Generate a WireGuard private/public key pair using `wg genkey` and `wg pubkey`."""
        (returncode, private_key, stderr) = cls._run_command(["wg", "genkey"])
        private_key = private_key.strip()
        public_key = cls.get_pubkey(private_key)
        return private_key, public_key
