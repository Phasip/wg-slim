"""Thin wrappers around the `wg`, `wg-quick` and `ip` commands."""

from __future__ import annotations

import logging
import subprocess
from typing import Optional
import tempfile

logger = logging.getLogger(__name__)


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
