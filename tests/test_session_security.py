"""Session lifetime and API-level robustness tests."""

from datetime import datetime, timedelta, timezone

import yaml

import wg_api


def login(client, password="testpassword"):
    response = client.post("/api/login", json={"password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def change_password(client, auth, current="testpassword", new="new-password"):
    return client.put(
        "/api/settings/password",
        headers=auth,
        json={"current_password": current, "new_password": new, "confirm_password": new},
    )


class TestPasswordChangeRevokesSessions:
    """Rotating the password must cut off sessions created with the old one."""

    def test_other_sessions_are_revoked(self, unauth_api_client):
        stolen = login(unauth_api_client)
        admin = login(unauth_api_client)

        assert unauth_api_client.get("/api/server", headers=stolen).status_code == 200

        assert change_password(unauth_api_client, admin).status_code == 200

        assert unauth_api_client.get("/api/server", headers=stolen).status_code == 401

    def test_caller_keeps_its_own_session(self, unauth_api_client):
        admin = login(unauth_api_client)

        assert change_password(unauth_api_client, admin).status_code == 200

        assert unauth_api_client.get("/api/server", headers=admin).status_code == 200

    def test_new_password_is_required_for_new_logins(self, unauth_api_client):
        admin = login(unauth_api_client)
        change_password(unauth_api_client, admin)

        assert unauth_api_client.post("/api/login", json={"password": "testpassword"}).status_code == 403
        assert unauth_api_client.post("/api/login", json={"password": "new-password"}).status_code == 200

    def test_failed_password_change_keeps_sessions(self, unauth_api_client):
        other = login(unauth_api_client)
        admin = login(unauth_api_client)

        assert change_password(unauth_api_client, admin, current="wrong").status_code == 403

        assert unauth_api_client.get("/api/server", headers=other).status_code == 200


class TestTokenExpiry:
    def test_expired_tokens_are_pruned_on_login(self, unauth_api_client):
        app = unauth_api_client.app
        login(unauth_api_client)
        stale = "stale-token"
        app.state.active_tokens[stale] = datetime.now(timezone.utc) - timedelta(hours=1)

        login(unauth_api_client)

        assert stale not in app.state.active_tokens

    def test_expired_token_is_rejected(self, unauth_api_client):
        auth = login(unauth_api_client)
        app = unauth_api_client.app
        for token in list(app.state.active_tokens):
            app.state.active_tokens[token] = datetime.now(timezone.utc) - timedelta(seconds=1)

        assert unauth_api_client.get("/api/server", headers=auth).status_code == 401

    def test_prune_keeps_valid_tokens(self, unauth_api_client):
        auth = login(unauth_api_client)
        wg_api.prune_expired_tokens(unauth_api_client.app)
        assert unauth_api_client.get("/api/server", headers=auth).status_code == 200


class TestMalformedPeerRobustness:
    """A peer edited into an odd shape must not take down unrelated endpoints."""

    def test_wg_show_survives_peer_without_public_key(self, unauth_api_client, mock_wg_manager):
        mock_wg_manager["wg show wg1"] = (0, "interface: wg1\npeer: peer2_public_key\n  latest handshake: 1 minute ago", "")
        auth = login(unauth_api_client)
        cm = unauth_api_client.app.state.config_manager
        malformed = next(p for p in cm.config.peers if p.name == "peer1")
        malformed.as_peer = "AllowedIPs = 10.0.0.2/32"

        response = unauth_api_client.get("/api/wg-show", headers=auth)

        assert response.status_code == 200
        body = response.json()
        assert body["peer1"] == "[Peer inactive in WireGuard]"
        # the healthy peer is still reported correctly
        assert "latest handshake" in body["peer2"]

    def test_renaming_server_peer_returns_400_and_keeps_working(self, unauth_api_client):
        auth = login(unauth_api_client)
        peer = yaml.safe_load(unauth_api_client.get("/api/peers/server/yaml", headers=auth).json()["yaml"])
        peer["name"] = "renamed"

        response = unauth_api_client.put("/api/peers/server/yaml", headers=auth, json={"yaml": yaml.dump(peer)})
        assert response.status_code == 400
        assert "must match an existing peer" in response.json()["error"]

        # Before the fix this instance was broken until restart
        assert unauth_api_client.post("/api/peers", headers=auth, json={"name": "newpeer"}).status_code == 201
        assert unauth_api_client.get("/api/server/yaml", headers=auth).status_code == 200

    def test_duplicate_peer_name_returns_400(self, unauth_api_client):
        auth = login(unauth_api_client)
        peer = yaml.safe_load(unauth_api_client.get("/api/peers/peer1/yaml", headers=auth).json()["yaml"])
        peer["name"] = "peer2"

        response = unauth_api_client.put("/api/peers/peer1/yaml", headers=auth, json={"yaml": yaml.dump(peer)})

        assert response.status_code == 400
        assert "Duplicate peer name" in response.json()["error"]

    def test_malformed_config_put_returns_400(self, unauth_api_client):
        auth = login(unauth_api_client)
        for payload in ["just-a-string", "- a\n- b", "server: {}\n"]:
            response = unauth_api_client.put("/api/config", headers=auth, json={"yaml": payload})
            assert response.status_code == 400, f"{payload!r} produced {response.status_code}"

    def test_alias_bomb_config_put_returns_400(self, unauth_api_client):
        auth = login(unauth_api_client)
        bomb = 'a: &a ["x","x","x"]\nb: &b [*a,*a,*a]\nc: [*b,*b,*b]\n'

        response = unauth_api_client.put("/api/config", headers=auth, json={"yaml": bomb})

        assert response.status_code == 400
        assert "aliases" in response.json()["error"]
