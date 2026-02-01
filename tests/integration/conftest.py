"""Pytest fixtures for integration tests (clean SDK-first file).

This file provides a small, consistent set of fixtures that use the Python
Docker SDK exclusively. It intentionally fails fast when the SDK or daemon
is not available.
"""

import os
import fcntl
import socket
import shutil
import tempfile
import time
import uuid
from pathlib import Path

import pytest
import requests
import docker
from contextlib import contextmanager
from types import SimpleNamespace
from config_model import SyncedConfigManager


# MultiLock to coordinate image builds across xdist workers, takes a folder and worker name as argument.
# Folder is filled with master lock and worker locks, first one to create master lock becomes builder
# Last one to remove worker lock becomes destroyer
class FileLock:
    def __init__(self, lock_path: str):
        self.fd = os.open(lock_path, os.O_CREAT | os.O_RDWR)

    def __enter__(self):
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        # self.f is just a convenience, not needed for the locking functionality.
        self.f = open(self.fd, mode="r+", closefd=False)
        self.f.seek(0)
        return self.f

    def __exit__(self, exc_type, exc_value, traceback):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        self.f.close()


# Synchronization lock that ensures all lockers will finish unlocking at the same time
# Additionally provides is_first == True boolean to the first locker
class MultiFileLock:
    def __init__(self, state_path: str, worker_name: str):
        self.worker_name = worker_name
        self.state_path = state_path

    def __enter__(self):
        with FileLock(self.state_path) as f:
            data = f.read().splitlines()
            assert self.worker_name not in data  # Sanity check that we are not reusing broken state
            is_first = len(data) == 0
            if not is_first:
                f.write("\n")  # ensure newline before appending
            f.write(f"{self.worker_name}")
        return is_first

    def __exit__(self, exc_type, exc_value, traceback):
        with FileLock(self.state_path) as f:
            data = f.read().splitlines()
            # Raise exception if the state file has been corrupted
            assert self.worker_name in data
            data.remove(self.worker_name)
            if len(data) == 0:
                os.remove(self.state_path)
            else:
                f.seek(0)
                f.write("\n".join(data))
                f.truncate()  # Truncate last so we could poll for file size zero and never remove the file

        # Wait for all workers to unlock
        while os.path.exists(self.state_path):
            time.sleep(0.5)


PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
IMAGE_NAME = "wg-slim-test:latest"
CONTAINER_PREFIX = "wg-slim-server-"
NETWORK_PREFIX = "wg-test-network-"


def get_docker_client():
    client = docker.from_env()
    client.ping()
    return client


@contextmanager
def run_container(*args, **kwargs):
    """Run a container and ensure it is stopped/removed when the context exits.

    Uses the local Docker client returned by `get_docker_client()` instead of
    requiring the caller to pass a client.
    """
    client = get_docker_client()
    kwargs.setdefault("detach", True)
    container = client.containers.run(*args, **kwargs)
    try:
        yield container
    finally:
        container.stop()
        container.remove(force=True)


# def pytest_configure(config):
#    master = hasattr(config, "workerinput")
#    if master:
#        # TODO


def free_port_tcp():
    """Return a free TCP port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        return s.getsockname()[1]


def free_port_udp():
    """Return a free UDP port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", 0))
        return s.getsockname()[1]


def wait_for_healthcheck(base_url, timeout=30):
    url = f"{base_url}/api/health"
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    return False


def get_container_ip(container_name, network_name):
    client = get_docker_client()
    c = client.containers.get(container_name)
    return c.attrs["NetworkSettings"]["Networks"][network_name]["IPAddress"]


def run_command_in_container(container, command):
    """Run a command inside the given container using the low-level Docker API.

    Uses `get_docker_client()` to obtain the low-level API client.

    Returns an object with `.returncode`, `.stdout`, `.stderr` to match
    `subprocess.CompletedProcess`-like usage in tests.
    """
    client = get_docker_client()
    api = client.api
    exec_id = api.exec_create(container.id, command)
    out = api.exec_start(exec_id, demux=True)
    info = api.exec_inspect(exec_id)
    exit_code = info.get("ExitCode")
    # `exec_start(..., demux=True)` is guaranteed to return a (stdout, stderr) tuple
    stdout_bytes, stderr_bytes = out
    stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
    stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
    return SimpleNamespace(returncode=exit_code, stdout=stdout, stderr=stderr)


@pytest.fixture(scope="session")
def docker_image():
    client = get_docker_client()
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    lock_dir = tempfile.gettempdir()
    bl = MultiFileLock(os.path.join(lock_dir, "wg-slim-build.lock"), worker_id)
    dl = MultiFileLock(os.path.join(lock_dir, "wg-slim-rm.lock"), worker_id)
    target = "full" if os.environ.get("DOCKER_TEST_BUILD_FULL_TARGET") else "base"
    with dl as is_destroyer:
        with bl as is_builder:
            if is_builder:
                client.images.build(path=PROJECT_ROOT, tag=IMAGE_NAME, rm=True, target=target)
        # All exit at same time, so image is built
        yield IMAGE_NAME
    # All exit at the same time, so all workers are done
    if is_destroyer:
        client.images.remove(image=IMAGE_NAME, force=True)
        client.images.prune()


@pytest.fixture
def docker_network():
    client = get_docker_client()
    network_name = f"{NETWORK_PREFIX}{uuid.uuid4().hex[:8]}"
    net = client.networks.create(network_name)
    try:
        yield network_name
    finally:
        net.remove()


@pytest.fixture
def wg_slim_container(docker_image, docker_network):
    web_port = free_port_tcp()
    wg_port = free_port_udp()
    container_name = f"{CONTAINER_PREFIX}{uuid.uuid4().hex[:8]}"
    tmpdir = tempfile.mkdtemp()

    ports = {"5000/tcp": web_port, "51820/udp": wg_port}
    if os.environ.get("DOCKER_TEST_BUILD_FULL_TARGET"):
        volumes = {tmpdir: {"bind": "/data", "mode": "rw"}}
    else:
        volumes = {tmpdir: {"bind": "/data", "mode": "rw"}, PROJECT_ROOT: {"bind": "/app", "mode": "rw"}}

    # Produce a complete initial config and pass as YAML text via INITIAL_CONFIG
    # Use the load_or_create method to create the config
    fallback_config = """\
basic:
  password: testpassword123
  bind_addr: "5000"
server:
  name: server
  interface_name: wg0
"""
    initial_cfg_path = os.path.join(tmpdir, "initial_config.yaml")
    SyncedConfigManager.load_or_create(file_path=initial_cfg_path, fallback_config_data=fallback_config)
    with open(initial_cfg_path, "r") as _f:
        initial_cfg_text = _f.read()

    with run_container(
        docker_image,
        name=container_name,
        network=docker_network,
        ports=ports,
        cap_add=["NET_ADMIN", "SYS_MODULE"],
        sysctls={"net.ipv4.ip_forward": "1"},
        environment={"INITIAL_CONFIG": initial_cfg_text},
        volumes=volumes,
    ) as container:
        base_url = f"http://localhost:{web_port}"
        if not wait_for_healthcheck(base_url):
            logs = container.logs(stdout=True, stderr=True, tail=200)
            print(f"Container logs:\n{logs}")
            pytest.fail("wg-slim container did not become healthy")

        server_ip = get_container_ip(container_name, docker_network)

        try:
            yield SimpleNamespace(container=container, server_ip=server_ip, base_url=base_url)
        finally:
            shutil.rmtree(tmpdir)


wg_slim_container2 = wg_slim_container  # Alias for tests that want multiple containers


@pytest.fixture
def container_simple(wg_slim_container):
    return wg_slim_container.base_url


@pytest.fixture
def create_authenticated_session(container_simple):
    """Return an authenticated `requests.Session` for integration tests.

    Uses the `container_simple` fixture to locate the server and a fixed test password.
    """
    session = requests.Session()
    response = session.post(f"{container_simple}/api/login", json={"password": "testpassword123"})
    assert response.status_code == 200, f"Auth failed: {response.text}"
    token = response.json().get("access_token")
    session.headers.update({"Authorization": f"Bearer {token}"})
    return session
