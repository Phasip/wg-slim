import uuid
import time
import yaml


def test_docker_peer_edit_lifecycle(container_simple, create_authenticated_session):
    """Integration test: add peer, edit its YAML, disable it, then delete it."""
    session = create_authenticated_session

    peer_name = f"peer_edit-{uuid.uuid4().hex[:8]}"

    response = session.post(f"{container_simple}/api/peers", json={"name": peer_name})
    assert response.status_code == 201, f"Failed to add peer: {response.text}"

    time.sleep(2)

    response = session.get(f"{container_simple}/api/peers/{peer_name}/yaml")
    assert response.status_code == 200, f"Failed to get peer yaml: {response.text}"
    peer_yaml = response.json().get("yaml")
    assert peer_yaml is not None

    parsed = yaml.safe_load(peer_yaml)
    as_peer = parsed.get("as_peer", "")
    assert "AllowedIPs = 10." in as_peer, "Peer does not have AllowedIPs set"
    parsed["as_peer"] = as_peer.replace("AllowedIPs = 10.", "AllowedIPs = 11.")
    new_yaml = yaml.dump(parsed)

    response = session.put(
        f"{container_simple}/api/peers/{peer_name}/yaml",
        json={"yaml": new_yaml},
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 200, f"Failed to update peer yaml: {response.text}"

    response = session.post(f"{container_simple}/api/peers/{peer_name}/disable")
    assert response.status_code == 200, f"Failed to disable peer: {response.text}"

    response = session.get(f"{container_simple}/api/peers")
    assert response.status_code == 200
    peers = response.json().get("peers", [])
    matched = [p for p in peers if p.get("name") == peer_name]
    assert len(matched) == 1
    assert matched[0].get("enabled") is False

    response = session.delete(f"{container_simple}/api/peers/{peer_name}")
    assert response.status_code == 200, f"Failed to delete peer: {response.text}"

    response = session.get(f"{container_simple}/api/peers")
    assert response.status_code == 200
    peers = response.json().get("peers", [])
    assert all(p.get("name") != peer_name for p in peers)
