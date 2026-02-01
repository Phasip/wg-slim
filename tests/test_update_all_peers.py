import yaml

import wgslim_api_client


def test_update_all_peers_applies_template(generated_api_client, config_for_test_client):
    """Ensure `/api/update-all-peers` applies the template peer's as_peer fields to others."""
    # Prepare: set peer1's as_peer to include Endpoint and PersistentKeepalive
    peer1_yaml = generated_api_client.peers_peer_name_yaml_get("peer1")
    parsed = yaml.safe_load(peer1_yaml.yaml)

    # Modify as_peer in the YAML to include Endpoint and PersistentKeepalive
    parsed["as_peer"] = "PublicKey = peer1_public_key\nEndpoint = templ.example.com:51820\nPersistentKeepalive = 42\nAllowedIPs = 10.0.0.2/32\n"
    new_yaml = yaml.dump(parsed)

    generated_api_client.peers_peer_name_yaml_put("peer1", wgslim_api_client.PeersPeerNameYamlPutRequest(yaml=new_yaml))

    # Call update-all-peers using peer1 as template
    generated_api_client.update_all_peers_post(wgslim_api_client.UpdateAllPeersPostRequest(template_peer="peer1"))

    # Check that peer2's as_peer now contains Endpoint and PersistentKeepalive
    peers_response = generated_api_client.peers_get()
    peers = peers_response.peers

    peer2 = next((p for p in peers if p.name == "peer2"), None)
    assert peer2 is not None, "peer2 missing"
    as_peer = peer2.as_peer or ""
    assert "Endpoint = templ.example.com:51820" in as_peer
    assert "PersistentKeepalive = 42" in as_peer
    # PublicKey should remain unchanged for peer2
    assert "peer2_public_key" in as_peer
