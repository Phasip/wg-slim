"""Unit tests for FwRulesSyncService, with `nft` mocked out."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from config_model import ConfigSyncException
from fw_sync_service import FwRulesSyncService


def make_service(ruleset):
    config_manager = MagicMock()
    config_manager.render_server_fw_rules.return_value = ruleset
    return FwRulesSyncService(config_manager=config_manager)


def test_unchanged_ruleset_is_applied_once():
    service = make_service("chain c { }")
    with patch("fw_sync_service.subprocess.run") as run:
        service.sync_now()
        service.sync_now()
    assert run.call_count == 1


def test_failed_ruleset_is_retried():
    service = make_service("chain c { }")
    failure = subprocess.CalledProcessError(1, ["nft"], output="", stderr="syntax error")
    with patch("fw_sync_service.subprocess.run", side_effect=failure):
        with pytest.raises(ConfigSyncException):
            service.sync_now()
    with patch("fw_sync_service.subprocess.run") as run:
        service.sync_now()
    assert run.call_count == 1
