"""Firewall rules sync service.

Watches the configuration for changes to `server.fw_rules`, renders the
template via `SyncedConfigManager.render_server_fw_rules()` and applies the
resulting nftables ruleset using `nft -f`, inside the `inet wgslim_fwrules`
table.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile


from config_model import SyncedConfigManager, ConfigSyncException

logger = logging.getLogger(__name__)

# `inet` so the rules apply to IPv6 as well as IPv4. Family-specific
# matches such as `ip saddr` keep working inside an inet table.
FAMILY = "inet"
TABLE = "wgslim_fwrules"
LEGACY_FAMILY = "ip"
LEGACY_TABLE = "wgeasy_fwrules"


class FwRulesSyncService:
    """Watches YAML config and applies nftables rules when they change."""

    def __init__(self, config_manager: "SyncedConfigManager") -> None:
        self.config_manager = config_manager

        self._last_ruleset = None

    def sync_now(self) -> None:
        """Render `fw_rules` and apply via `nft -f`.

        If no `fw_rules` template is configured this is a no-op.
        """
        rendered = self.config_manager.render_server_fw_rules()
        if rendered:
            rendered = rendered.strip()
        if rendered == self._last_ruleset:
            return
        # Also drop the IPv4-only table used by earlier versions, or its
        # rules would keep applying next to the new ones.
        wrapped = f"destroy table {LEGACY_FAMILY} {LEGACY_TABLE};\ndestroy table {FAMILY} {TABLE};\n"

        if rendered:
            wrapped += f"table {FAMILY} {TABLE} {{\n{rendered}\n}}\n"
        logger.debug(f"Full fw ruleset: {wrapped}")
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=True) as tf:
                tf.write(wrapped)
                tf.flush()
                logger.debug("Applying nftables rules from temp file %s", tf.name)
                subprocess.run(["nft", "-f", tf.name], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            raise ConfigSyncException(f"nft failed: returncode={e.returncode} stdout={e.stdout!r} stderr={e.stderr!r}") from e
        except OSError as e:
            raise ConfigSyncException(f"OS error applying fw_rules: {e}") from e
        # Only remember a ruleset once nft accepted it, so a failed one is
        # retried rather than skipped as "unchanged".
        self._last_ruleset = rendered
