import pytest

from wgslim_api_client.exceptions import UnauthorizedException


def test_login_logout_revokes_token(generated_api_client):
    """Login, access protected endpoint, logout, then verify token no longer works."""
    server = generated_api_client.server_get()
    assert server is not None

    # Call the logout endpoint to revoke the token
    generated_api_client.logout_get()

    # Subsequent request with the same token should be unauthorized
    with pytest.raises(UnauthorizedException):
        generated_api_client.server_get()


def test_token_replaced_with_random_string_fails(generated_api_client):
    """Login, verify token works, then replace Authorization header with random string and expect 401."""
    server = generated_api_client.server_get()
    assert server is not None

    # Replace header with an invalid random token string and assert it's inactive
    generated_api_client.api_client.configuration.access_token = "this-is-not-a-valid-token"
    with pytest.raises(UnauthorizedException):
        generated_api_client.server_get()
