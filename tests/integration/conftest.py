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
import xdist
from contextlib import contextmanager
from types import SimpleNamespace
from config_model import SyncedConfigManager


# Simple flock-based mutex, used both as a plain lock and (via the returned
# file handle) as small persistent storage for coordinating xdist workers.
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


PROJECT_ROOT = str(Path(__file__).resolve().parents[2])
IMAGE_NAME = "wg-slim-test:latest"
CONTAINER_PREFIX = "wg-slim-server-"
NETWORK_PREFIX = "wg-test-network-"

# Shared Docker image lifecycle across xdist workers.
#
# Building the `full` target takes real time, so it is built once and reused
# by every worker. Previously this was coordinated by having the first
# worker to *arrive* at the fixture build, and the last to *leave* remove it
# -- but pytest fixtures are lazy, so a worker whose first Docker-dependent
# test happens to run late doesn't register until then. That let an earlier
# cohort finish its own round and delete the image (or leave a stale
# lockfile) before the late worker ever used it, causing spurious rebuilds
# and "No such image" failures under `-n auto`.
#
# Fixed by decoupling the two concerns:
#  - Building is a plain idempotent, lock-guarded "build if missing" -- order
#    of arrival doesn't matter.
#  - Removal is gated by a countdown seeded from PYTEST_XDIST_WORKER_COUNT,
#    the true fixed number of workers for this run (set by pytest-xdist
#    itself), decremented from `pytest_sessionfinish`. Unlike a fixture, that
#    hook fires for every worker unconditionally, whether or not it ever
#    touched a Docker test, so the count can't be thrown off by workers that
#    show up (or never show up) to the fixture at different times.
_LOCK_DIR = tempfile.gettempdir()
_IMAGE_BUILD_LOCK = os.path.join(_LOCK_DIR, "wg-slim-build.lock")
_IMAGE_REFCOUNT_LOCK = os.path.join(_LOCK_DIR, "wg-slim-rm.lock")


def _worker_count():
    return int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", "1"))


def pytest_sessionfinish(session, exitstatus):
    """Remove the shared test image once every worker has finished with it.

    The xdist controller process runs this hook too, but never executes any
    tests or uses `docker_image` itself -- only the actual workers (or, in a
    non-distributed run, the single process) count toward the countdown.
    """
    if xdist.is_xdist_controller(session):
        return
    with FileLock(_IMAGE_REFCOUNT_LOCK) as f:
        raw = f.read().strip()
        remaining = (int(raw) if raw else _worker_count()) - 1
        f.seek(0)
        f.write(str(remaining))
        f.truncate()
    if remaining <= 0:
        os.remove(_IMAGE_REFCOUNT_LOCK)
        client = get_docker_client()
        try:
            client.images.remove(image=IMAGE_NAME, force=True)
            client.images.prune()
        except docker.errors.ImageNotFound:
            pass


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
    with FileLock(_IMAGE_BUILD_LOCK):
        try:
            client.images.get(IMAGE_NAME)
        except docker.errors.ImageNotFound:
            client.images.build(path=PROJECT_ROOT, tag=IMAGE_NAME, rm=True, target="full")
    yield IMAGE_NAME
    # Removal is handled by `pytest_sessionfinish`, once every worker is done.


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
    volumes = {tmpdir: {"bind": "/data", "mode": "rw"}}

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
