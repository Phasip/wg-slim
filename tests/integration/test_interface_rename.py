import time
import yaml
from conftest import get_docker_client, run_command_in_container


def test_docker_interface_rename(wg_slim_container, container_simple, create_authenticated_session):
    """Integration test: change the server `interface_name` and verify the running interface updates."""
    session = create_authenticated_session

    # Get the full config YAML (so PUT will accept the same structure)
    response = session.get(f"{container_simple}/api/config")
    assert response.status_code == 200, f"Failed to get full config: {response.text}"
    config_yaml = response.json().get("config")
    assert config_yaml is not None

    parsed = yaml.safe_load(config_yaml)
    # top-level structure contains 'server' with 'interface_name'
    old_interface = parsed.get("server", {}).get("interface_name")
    # Choose a new interface name that is unlikely to conflict
    new_interface = "wg-renamed"
    if old_interface == new_interface:
        new_interface = "wg-renamed2"

    # Update and PUT the full config
    parsed["server"]["interface_name"] = new_interface
    new_yaml = yaml.dump(parsed)

    response = session.put(f"{container_simple}/api/config", json={"yaml": new_yaml})
    assert response.status_code == 200, f"Failed to update config: {response.text}"

    # Give the sync service a moment to react
    time.sleep(3)

    container_name = wg_slim_container.container.name

    # Check that the new interface exists inside the container
    client = get_docker_client()
    container = client.containers.get(container_name)
    res_new = run_command_in_container(container, ["ip", "link", "show", "dev", new_interface])
    assert res_new.returncode == 0, f"New interface {new_interface} not found: {res_new.stderr}"

    # The old interface should no longer be present
    if old_interface:
        res_old = run_command_in_container(container, ["ip", "link", "show", "dev", old_interface])
        assert res_old.returncode != 0, f"Old interface {old_interface} still present: {res_old.stdout}"
