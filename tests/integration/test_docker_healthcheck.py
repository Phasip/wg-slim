import requests


def assert_health_ok(container_simple):
    """Simple helper to assert /api/health returns healthy."""
    healthcheck_url = f"{container_simple}/api/health"
    response = requests.get(healthcheck_url)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_healthcheck_endpoint(container_simple):
    assert_health_ok(container_simple)


def test_auth_status_endpoint(container_simple):
    login_url = f"{container_simple}/login"
    response = requests.get(login_url)
    assert response.status_code == 200


def test_server_status_endpoint(container_simple):
    session = requests.Session()

    server_status_url = f"{container_simple}/api/server/status"
    response = session.get(server_status_url)
    assert response.status_code == 401
    login_url = f"{container_simple}/api/login"
    auth_response = session.post(login_url, json={"password": "testpassword123"})
    assert auth_response.status_code == 200
    token = auth_response.json()["access_token"]
    session.headers.update({"Authorization": f"Bearer {token}"})

    response = session.get(server_status_url)
    assert response.status_code == 200
    server_data = response.json()
    assert "status" in server_data
