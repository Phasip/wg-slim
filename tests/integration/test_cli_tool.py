"""Integration test for the wg-slim CLI tool."""

import json
from types import SimpleNamespace
from tests.integration.conftest import run_command_in_container


def run_cli_in_container(container, command_args):
    """Execute wg_cli.py command inside the container."""
    # Set PYTHONPATH to include generated client (when using base target with mounted /app)
    cmd = ["sh", "-c", f"PYTHONPATH=/app/openapi_generated/python-client:$PYTHONPATH python3 /app/wgslim_cli.py {' '.join(command_args)}"]
    result = run_command_in_container(container, cmd)

    return SimpleNamespace(exit_code=result.returncode, output=result.stdout, stderr=result.stderr)


def test_cli_get_config(wg_slim_container):
    """Test CLI get-config command."""
    result = run_cli_in_container(wg_slim_container.container, ["get-config"])

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    assert "basic:" in result.output
    assert "password:" in result.output
    assert "server:" in result.output


def test_cli_list_peers_empty(wg_slim_container):
    """Test CLI list-peers command with no peers."""
    result = run_cli_in_container(wg_slim_container.container, ["list-peers"])

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    # Note: The server itself appears as a peer


def test_cli_add_peer(wg_slim_container):
    """Test CLI add-peer command."""
    result = run_cli_in_container(
        wg_slim_container.container,
        ["add-peer", "test_peer"],
    )

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    assert "added successfully" in result.output


def test_cli_list_peers_with_peer(wg_slim_container):
    """Test CLI list-peers command with peers."""
    run_cli_in_container(
        wg_slim_container.container,
        ["add-peer", "peer1"],
    )

    result = run_cli_in_container(wg_slim_container.container, ["list-peers"])

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    assert "peer1" in result.output


def test_cli_list_peers_json(wg_slim_container):
    """Test CLI list-peers command with JSON output."""
    run_cli_in_container(
        wg_slim_container.container,
        ["add-peer", "peer_json"],
    )

    result = run_cli_in_container(wg_slim_container.container, ["list-peers", "--json"])

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    peers = json.loads(result.output)
    assert isinstance(peers, list)
    assert len(peers) > 0


def test_cli_get_peer_config(wg_slim_container):
    """Test CLI get-peer-config command."""
    run_cli_in_container(
        wg_slim_container.container,
        ["add-peer", "peer2"],
    )

    result = run_cli_in_container(wg_slim_container.container, ["get-peer-config", "peer2"])

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    assert "[Interface]" in result.output
    assert "[Peer]" in result.output


def test_cli_delete_peer(wg_slim_container):
    """Test CLI delete-peer command."""
    run_cli_in_container(
        wg_slim_container.container,
        ["add-peer", "peer3"],
    )

    result = run_cli_in_container(wg_slim_container.container, ["delete-peer", "peer3"])

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
    assert "deleted successfully" in result.output

    list_result = run_cli_in_container(wg_slim_container.container, ["list-peers"])
    assert "peer3" not in list_result.output


def test_cli_with_explicit_credentials(wg_slim_container):
    """Test CLI with explicit host, port, and password parameters."""
    result = run_cli_in_container(
        wg_slim_container.container,
        [
            "--host",
            "localhost",
            "--port",
            "5000",
            "--password",
            "testpassword123",
            "list-peers",
        ],
    )

    assert result.exit_code == 0, f"CLI failed: {result.stderr}"
