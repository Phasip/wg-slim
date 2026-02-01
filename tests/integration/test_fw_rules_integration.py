import yaml
import pytest


def test_fw_rules_saved_via_api(container_simple, create_authenticated_session):
    """Integration test: ensure server.fw_rules can be set via the config API and persisted.

    This uses the running container fixture so it exercises the full codepath
    (including validation and persistence) instead of the local unit helpers.
    """
    base = container_simple
    session = create_authenticated_session

    # Fetch current config
    r = session.get(f"{base}/api/config")
    assert r.status_code == 200
    cfg_yaml = r.json()["config"]
    data = yaml.safe_load(cfg_yaml)

    # Add a multiline nftables template to server.fw_rules
    # Use valid nft batch file syntax (chain definition within table block)
    template = "chain input {\n    type filter hook input priority 0;\n    iif {{interface_name}} ip saddr {{AllowedIPs}} accept\n}\n"
    data.setdefault("server", {})["fw_rules"] = template

    new_yaml = yaml.safe_dump(data, sort_keys=False)

    # PUT the updated config
    r = session.put(f"{base}/api/config", json={"yaml": new_yaml})
    if r.status_code != 200:
        # Surface server response for debugging
        pytest.fail(f"PUT /api/config failed: {r.status_code} - {r.text}")

    # Re-fetch and verify it's persisted
    r = session.get(f"{base}/api/config")
    assert r.status_code == 200
    loaded = yaml.safe_load(r.json()["config"])
    assert loaded.get("server", {}).get("fw_rules") is not None
    assert "{{interface_name}}" in loaded["server"]["fw_rules"]
    assert "{{AllowedIPs}}" in loaded["server"]["fw_rules"]
