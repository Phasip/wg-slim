"""Tests for the main.py initialize_config function."""

import yaml

from wg_api import ENV_INITIAL_CONFIG, DEFAULT_INITIAL_CONFIG
from config_model import SyncedConfigManager


def test_uses_values_from_config(config_for_test_client, monkeypatch):
    """Test that values from config take precedence over env."""
    # Provide some dummy initial config via ENV_INITIAL_CONFIG; since a
    # config file exists for this test, the env value should be ignored.
    monkeypatch.setenv(ENV_INITIAL_CONFIG, 'basic:\n  password: envpassword\n  bind_addr: "9000"\nserver:\n  interface_name: wg9\n')

    SyncedConfigManager.load_or_create(config_for_test_client, DEFAULT_INITIAL_CONFIG)

    with open(config_for_test_client, "r") as f:
        saved = yaml.safe_load(f)
    assert saved["basic"]["password"] == "testpassword"
    assert saved["server"]["interface_name"] == "wg1"
    assert saved["basic"]["bind_addr"] == "5000"
