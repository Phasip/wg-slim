def test_docker_server_logs(container_simple, create_authenticated_session):
    """Simple check: `/api/server/logs` returns a non-empty `logs` list."""
    session = create_authenticated_session

    resp = session.get(f"{container_simple}/api/server/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data.get("logs"), list)
    assert len(data["logs"]) > 0
