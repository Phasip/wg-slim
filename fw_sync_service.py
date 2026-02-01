"""Firewall rules sync service.

Watches the configuration for changes to `server.fw_rules`, renders the
template via `SyncedConfigManager.render_server_fw_rules()` and applies the
resulting nftables ruleset using `nft -f`.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile


from config_model import SyncedConfigManager, ConfigSyncException

logger = logging.getLogger(__name__)


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
        self._last_ruleset = rendered
        FAMILY = "ip"
        TABLE = "wgeasy_fwrules"
        wrapped = f"destroy table {FAMILY} {TABLE};\n"

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
