import os
import tempfile
import shutil
import uuid
import requests

from conftest import run_container, free_port_tcp, free_port_udp, wait_for_healthcheck, PROJECT_ROOT


def test_start_container_without_config(docker_image, docker_network):
    """Start the container with no config file and no INITIAL_CONFIG env.

    The application should create an initial config with the expected
    defaults: password `password`, bind_addr `5000`, server interface_name
    `wg0`, server named `server` and a peer named `server`.
    """
    web_port = free_port_tcp()
    wg_port = free_port_udp()
    container_name = f"wg-slim-server-{uuid.uuid4().hex[:8]}"
    tmpdir = tempfile.mkdtemp()

    ports = {"5000/tcp": web_port, "51820/udp": wg_port}
    if os.environ.get("DOCKER_TEST_BUILD_FULL_TARGET"):
        volumes = {tmpdir: {"bind": "/data", "mode": "rw"}}
    else:
        volumes = {tmpdir: {"bind": "/data", "mode": "rw"}, PROJECT_ROOT: {"bind": "/app", "mode": "rw"}}

    with run_container(
        docker_image,
        name=container_name,
        network=docker_network,
        ports=ports,
        cap_add=["NET_ADMIN", "SYS_MODULE"],
        sysctls={"net.ipv4.ip_forward": "1"},
        volumes=volumes,
    ) as container:
        base_url = f"http://localhost:{web_port}"

        if not wait_for_healthcheck(base_url):
            logs = container.logs(stdout=True, stderr=True, tail=200)
            print(f"Container logs:\n{logs}")
            raise AssertionError("wg-slim container did not become healthy")

        # The default initial password expected from the auto-created config
        session = requests.Session()
        auth_resp = session.post(f"{base_url}/api/login", json={"password": "password"})
        assert auth_resp.status_code == 200, f"Login failed: {auth_resp.status_code} {auth_resp.text}"
        token = auth_resp.json().get("access_token")
        assert token, "No access token returned"
        session.headers.update({"Authorization": f"Bearer {token}"})

        # Verify server metadata
        srv_resp = session.get(f"{base_url}/api/server")
        assert srv_resp.status_code == 200, f"Server endpoint failed: {srv_resp.text}"
        srv = srv_resp.json()
        assert srv.get("name") == "server"
        assert srv.get("interface_name") == "wg0"

        # Verify peers include a peer named `server`
        peers_resp = session.get(f"{base_url}/api/peers")
        assert peers_resp.status_code == 200, f"Peers endpoint failed: {peers_resp.text}"
        peers = peers_resp.json().get("peers", [])
        matched = [p for p in peers if p.get("name") == "server"]
        assert len(matched) == 1, "Expected a peer named 'server' in auto-created config"

    shutil.rmtree(tmpdir)
