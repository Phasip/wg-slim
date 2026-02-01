"""WireGuard configuration sync service."""

from __future__ import annotations

import logging
import os
import subprocess


import wg_manager
from config_model import SyncedConfigManager, ConfigSyncException

logger = logging.getLogger(__name__)


class WgConfigSyncService:
    """Watches YAML config and syncs WireGuard interface."""

    def __init__(self, config_manager: "SyncedConfigManager") -> None:
        """Initialize the sync service."""
        self.config_manager = config_manager
        # Track the currently active interface so renames can be handled cleanly
        self.active_interface = self.config_manager.config.server.interface_name
        self.output_dir = "/etc/wireguard"

    def sync_now(self) -> None:
        """Perform an immediate sync of the configuration."""
        logger.info("Starting configuration sync...")

        interface = self.config_manager.config.server.interface_name
        output_config = os.path.join(self.output_dir, f"{interface}.conf")

        if interface != self.active_interface and wg_manager.WgManager.is_interface_up(self.active_interface):
            prev_conf = os.path.join(self.output_dir, f"{self.active_interface}.conf")
            logger.info("Interface name changed from %s to %s; bringing down %s", self.active_interface, interface, self.active_interface)
            wg_manager.WgManager.bring_down(prev_conf)

        os.makedirs(self.output_dir, exist_ok=True)
        content = self.config_manager.generate_server_config(self.config_manager.config.server.name)
        with open(output_config, "w") as f:
            f.write(content)
        logger.info("Generated config file: %s", output_config)

        logger.info("Syncing configuration to interface %s...", interface)
        if not wg_manager.WgManager.is_interface_up(interface):
            logger.info("Interface %s not up; bringing up with wg-quick", interface)
            try:
                wg_manager.WgManager.bring_up(output_config)
            except subprocess.CalledProcessError as e:
                raise ConfigSyncException(f"Failed to bring up interface {interface}: {e}") from e
        else:
            wg_manager.WgManager.sync_config(interface, output_config)

        # Record the interface we just synced so future renames are detected
        self.active_interface = interface
        logger.info("Configuration sync completed successfully")
