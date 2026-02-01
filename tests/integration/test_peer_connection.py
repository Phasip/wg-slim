import time
import uuid
import json
from conftest import get_docker_client, run_command_in_container, run_container


def test_add_peer_get_config_and_connect(wg_slim_container, container_simple, docker_network, create_authenticated_session):
    server_ip = wg_slim_container.server_ip

    peer_name = "test-peer-1"
    response = create_authenticated_session.post(f"{container_simple}/api/peers", json={"name": peer_name})
    assert response.status_code == 201, f"Failed to add peer: {response.text}"
    print(f"\n[ADD PEER] Response: {response.json()}")

    resp = create_authenticated_session.get(f"{container_simple}/api/server/status")
    assert resp.status_code == 200, f"Failed to get server status: {resp.text}"
    print(f"\n[SERVER STATUS after adding peer]:\n{json.dumps(resp.json(), indent=2)}")

    response = create_authenticated_session.get(f"{container_simple}/api/server/sync-status")
    print(f"\n[SYNC STATUS]:\\n{json.dumps(response.json(), indent=2)}")

    server_client = get_docker_client()
    server_container = server_client.containers.get(wg_slim_container.container.name)

    result = run_command_in_container(server_container, ["wg", "show"])
    print(f"\n[WG SHOW on server]:\\n{result.stdout}\\nstderr: {result.stderr}")

    result = run_command_in_container(server_container, ["cat", "/etc/wireguard/wg0.conf"])
    print(f"\n[SERVER WG0.CONF]:\\n{result.stdout}")

    result = run_command_in_container(server_container, ["ip", "addr"])
    print(f"\n[IP ADDR on server]:\\n{result.stdout}")

    response = create_authenticated_session.get(f"{container_simple}/api/peers/{peer_name}/config")
    assert response.status_code == 200, f"Failed to get peer config: {response.text}"
    peer_config = response.json()["config"]
    print(f"\n[PEER CONFIG]:\n{peer_config}")

    lines = peer_config.splitlines()
    modified_lines = []
    for line in lines:
        if line.strip().startswith("Endpoint ="):
            modified_lines.append(f"Endpoint = {server_ip}:51820")
        elif line.strip().startswith("AllowedIPs ="):
            modified_lines.append("AllowedIPs = 10.0.0.0/24")
        else:
            modified_lines.append(line)

    modified_config = "\n".join(modified_lines)
    print(f"\n[MODIFIED CONFIG for client]:\n{modified_config}")

    client_container_name = f"wg-client-{uuid.uuid4().hex[:8]}"
    with run_container(
        "linuxserver/wireguard",
        name=client_container_name,
        network=docker_network,
        cap_add=["NET_ADMIN", "SYS_MODULE"],
        sysctls={"net.ipv4.conf.all.src_valid_mark": "1"},
    ) as client_container:
        time.sleep(6)

        # write the configuration into the client container using the SDK exec
        result = run_command_in_container(
            client_container,
            ["sh", "-c", f"cat > /config/wg_confs/wg0.conf << 'EOF'\n{modified_config}\nEOF"],
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to write config to client container: {result.stderr}")

        result = run_command_in_container(client_container, ["wg-quick", "up", "wg0"])
        print(f"\n[WG-QUICK UP] returncode={result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}")

        time.sleep(3)

        result = run_command_in_container(client_container, ["wg", "show"])
        print(f"\n[WG SHOW on client]:\n{result.stdout}")
        assert result.returncode == 0, f"wg show failed: {result.stderr}"
        assert "peer:" in result.stdout.lower() or "interface:" in result.stdout.lower(), f"WireGuard interface not properly configured: {result.stdout}"

        result = run_command_in_container(client_container, ["ping", "-c", "3", "-W", "2", "10.0.0.1"])
        ping_success = result.returncode == 0
        print(f"\n[PING 10.0.0.1] success={ping_success}\nstdout: {result.stdout}\nstderr: {result.stderr}")
        assert ping_success, f"Ping to 10.0.0.1 failed: {result.stdout}"

        time.sleep(2)

        response = create_authenticated_session.get(f"{container_simple}/api/peers")
        assert response.status_code == 200, f"Failed to get peers: {response.text}"
        peers_data = response.json()
        print(f"\n[GET PEERS]:\n{json.dumps(peers_data, indent=2)}")
        found = any(p.get("name") == peer_name for p in peers_data.get("peers", []))
        assert found, f"Peer {peer_name} not found in peers list"

        response = create_authenticated_session.get(f"{container_simple}/api/peers")
        assert response.status_code == 200, f"Failed to get peers: {response.text}"
        peers_data = response.json()
        print(f"\n[GET PEERS]:\n{json.dumps(peers_data, indent=2)}")
        assert len(peers_data["peers"]) >= 1

        found_peer = None
        for p in peers_data["peers"]:
            if p["name"] == peer_name:
                found_peer = p
                break
        assert found_peer is not None, f"Peer {peer_name} not found in peers list"

        response = create_authenticated_session.get(f"{container_simple}/api/server/status")
        assert response.status_code == 200, f"Failed to get server status: {response.text}"
        server_status = response.json()
        print(f"\n[SERVER STATUS]:\n{json.dumps(server_status, indent=2)}")

        assert server_status.get("status") == "up", f"Server interface is not running: {server_status}"
        assert server_status.get("is_running") is True, f"Server is_running is not True: {server_status}"
        # `stats` was removed from the API; ensure server reports running state
        assert server_status.get("is_running") is True


def test_peer_lifecycle_with_api(container_simple, create_authenticated_session):
    peer_name = f"lifecycle-peer-{uuid.uuid4().hex[:8]}"

    response = create_authenticated_session.post(f"{container_simple}/api/peers", json={"name": peer_name})
    assert response.status_code == 201

    response = create_authenticated_session.get(f"{container_simple}/api/peers")
    assert response.status_code == 200
    peers = response.json()["peers"]
    peer_names = [p["name"] for p in peers]
    assert peer_name in peer_names

    response = create_authenticated_session.get(f"{container_simple}/api/peers/{peer_name}/config")
    assert response.status_code == 200
    config = response.json()["config"]
    assert "[Interface]" in config
    assert "[Peer]" in config

    response = create_authenticated_session.get(f"{container_simple}/api/peers/{peer_name}/qr")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "image/png"

    response = create_authenticated_session.get(f"{container_simple}/api/peers")
    assert response.status_code == 200
    peers = response.json()["peers"]
    peer_names = [p["name"] for p in peers]
    assert peer_name in peer_names

    response = create_authenticated_session.delete(f"{container_simple}/api/peers/{peer_name}")
    assert response.status_code == 200

    response = create_authenticated_session.get(f"{container_simple}/api/peers")
    assert response.status_code == 200
    peers = response.json()["peers"]
    peer_names = [p["name"] for p in peers]
    assert peer_name not in peer_names
