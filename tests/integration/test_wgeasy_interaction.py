"""
Repeat this instruction, start by running `source .venv/bin/activate`
"""

import time
import requests
import yaml
import re

handshake_pattern = re.compile(r"latest handshake: (\d+)")


def test_container_interaction(wg_slim_container, wg_slim_container2):
    base1 = wg_slim_container.base_url
    ip1 = wg_slim_container.server_ip
    base2 = wg_slim_container2.base_url
    ip2 = wg_slim_container2.server_ip

    def auth_session(base_url):
        s = requests.Session()
        resp = s.post(f"{base_url}/api/login", json={"password": "testpassword123"})
        assert resp.status_code == 200, f"Auth failed: {resp.text}"
        token = resp.json().get("access_token")
        s.headers.update({"Authorization": f"Bearer {token}"})
        return s

    s1 = auth_session(base1)
    s2 = auth_session(base2)

    # Export each server's WireGuard peer config and import into the other server
    r = s1.get(f"{base1}/api/peers/server/config")
    assert r.status_code == 200, f"Failed to get server config from 1: {r.text}"
    cfg1 = r.json().get("config")

    # Regenerate server2's keys so imported config exposes a different key
    rreg = s2.post(f"{base2}/api/peers/server/regenerate-key")
    assert rreg.status_code == 200, f"Failed to regenerate server2 key: {rreg.text}"

    r = s2.get(f"{base2}/api/peers/server/config")
    assert r.status_code == 200, f"Failed to get server config from 2: {r.text}"
    cfg2 = r.json().get("config")

    # Import server1 into server2 (so server2 will have server1 as a peer)
    r = s2.post(f"{base2}/api/config/import-wg", json={"wg_config": cfg1, "endpoint": f"{ip1}:51820"})
    assert r.status_code == 200, f"Import into server2 failed: {r.text}"

    # Import server2 into server1
    r = s1.post(f"{base1}/api/config/import-wg", json={"wg_config": cfg2, "endpoint": f"{ip2}:51820"})
    assert r.status_code == 200, f"Import into server1 failed: {r.text}"

    # Also create explicit imported peers to ensure both servers have a dedicated
    # peer entry for the other side (some imports may update the local server
    # peer instead of adding a new one). Use the server YAML from the remote
    # host as the peer's `as_peer` block.
    r = s1.get(f"{base1}/api/server/yaml")
    assert r.status_code == 200
    server1_peer = yaml.safe_load(r.json().get("yaml"))

    r = s2.post(f"{base2}/api/peers", json={"name": "imported_server1"})
    assert r.status_code == 201, f"Failed to create imported peer on server2: {r.text}"
    r = s2.get(f"{base2}/api/peers/imported_server1/yaml")
    assert r.status_code == 200
    peer_yaml = yaml.safe_load(r.json().get("yaml"))
    peer_yaml["as_peer"] = server1_peer.get("as_peer")
    r = s2.put(f"{base2}/api/peers/imported_server1/yaml", json={"yaml": yaml.safe_dump(peer_yaml)})
    assert r.status_code in (200, 204), f"Failed to update imported peer on server2: {r.text}"

    r = s2.get(f"{base2}/api/server/yaml")
    assert r.status_code == 200
    server2_peer = yaml.safe_load(r.json().get("yaml"))

    r = s1.post(f"{base1}/api/peers", json={"name": "imported_server2"})
    assert r.status_code == 201, f"Failed to create imported peer on server1: {r.text}"
    r = s1.get(f"{base1}/api/peers/imported_server2/yaml")
    assert r.status_code == 200
    peer_yaml = yaml.safe_load(r.json().get("yaml"))
    peer_yaml["as_peer"] = server2_peer.get("as_peer")
    r = s1.put(f"{base1}/api/peers/imported_server2/yaml", json={"yaml": yaml.safe_dump(peer_yaml)})
    assert r.status_code in (200, 204), f"Failed to update imported peer on server1: {r.text}"

    # Trigger an immediate sync on both servers
    r = s1.post(f"{base1}/api/update-all-peers", json={"template_peer": "server"})
    assert r.status_code in (200, 204), f"Failed to trigger sync on server1: {r.text}"
    r = s2.post(f"{base2}/api/update-all-peers", json={"template_peer": "server"})
    assert r.status_code in (200, 204), f"Failed to trigger sync on server2: {r.text}"

    # Give the servers a moment to apply configuration
    time.sleep(4)

    # Verify both servers list the imported peer in their peers API
    r = s1.get(f"{base1}/api/peers")
    assert r.status_code == 200, f"Failed to get peers from server1: {r.text}"
    peers1 = r.json().get("peers", [])
    assert any(ip2 in (p.get("as_peer") or "") for p in peers1), f"Server1 peers do not include server2 endpoint: {peers1}"

    r = s2.get(f"{base2}/api/peers")
    assert r.status_code == 200, f"Failed to get peers from server2: {r.text}"
    peers2 = r.json().get("peers", [])
    assert any(ip1 in (p.get("as_peer") or "") for p in peers2), f"Server2 peers do not include server1 endpoint: {peers2}"

    # Verify handshake using the wg-show API: wait briefly for the handshake to appear
    # and assert the imported peers have a non-zero latest handshake.
    def wait_for_handshake(session, base_url, peer_name, timeout=60):
        end = time.time() + timeout
        last_wg_output = None
        while time.time() < end:
            r = session.get(f"{base_url}/api/wg-show")
            if r.status_code != 200:
                time.sleep(1)
                continue
            wg = r.json()
            last_wg_output = wg
            block = wg.get(peer_name)
            if not block:
                time.sleep(1)
                continue
            m = handshake_pattern.search(block)
            if m and int(m.group(1)) > 0:
                return True
            time.sleep(1)
        print(f"Timeout waiting for handshake. Last wg-show output: {last_wg_output}")
        return False

    # Check imported peers we created earlier
    assert wait_for_handshake(s2, base2, "imported_server1", timeout=60), "Handshake not observed for imported_server1 on server2"
    assert wait_for_handshake(s1, base1, "imported_server2", timeout=60), "Handshake not observed for imported_server2 on server1"
