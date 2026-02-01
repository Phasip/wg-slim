import time
import uuid
import yaml
import re
from contextlib import contextmanager
from conftest import run_container, run_command_in_container
from wg_utils import parse_wg_section


def api_add_peer(session, base_url: str, name: str):
    r = session.post(f"{base_url}/api/peers", json={"name": name})
    assert r.status_code == 201, f"Failed to add peer {name}: {r.text}"
    return r


def api_get_peer_config(session, base_url: str, name: str) -> str:
    r = session.get(f"{base_url}/api/peers/{name}/config")
    assert r.status_code == 200, f"Failed to get peer config {name}: {r.text}"
    return r.json()["config"]


def api_get_config(session, base_url: str):
    r = session.get(f"{base_url}/api/config")
    assert r.status_code == 200, f"Failed GET /api/config: {r.text}"
    return yaml.safe_load(r.json()["config"])


def api_put_config(session, base_url: str, yaml_text: str):
    yaml_payload = yaml.safe_dump(yaml_text, sort_keys=False)
    r = session.put(f"{base_url}/api/config", json={"yaml": yaml_payload})
    assert r.status_code == 200, f"PUT /api/config failed: {r.status_code} - {r.text}"
    return r


def run_ping_check(container, addr: str, count: int = 3, timeout: int = 2, deadline: int = 0, interval: float = 1.0, wait_for_fail=False):
    """
    Run a ping inside `container` to `addr`.

    If `deadline` > 0, poll until a successful ping (returncode==0) is observed
    or until the deadline (seconds) elapses, checking every `interval` seconds.
    If `deadline` == 0, perform a single immediate ping and return the result.
    On timeout, raise AssertionError with the last captured output.
    """
    if deadline and deadline > 0:
        end = time.time() + deadline
        last = None
        while time.time() < end:
            res = run_command_in_container(container, ["ping", "-c", str(count), "-W", str(timeout), addr])
            if not wait_for_fail and res.returncode == 0:
                return res
            if wait_for_fail and res.returncode != 0:
                return res
            last = res
            time.sleep(interval)
        # timed out
        if wait_for_fail:
            raise AssertionError(f"Ping did not fail within {deadline}s, last stdout: {getattr(last, 'stdout', None)}")
        raise AssertionError(f"Ping did not succeed within {deadline}s, last stdout: {getattr(last, 'stdout', None)}")

    return run_command_in_container(container, ["ping", "-c", str(count), "-W", str(timeout), addr])


def check_nft_ruleset(container, core_rule: str, present: bool = True, deadline: int = 0, interval: float = 1.0):
    """
    Check that `core_rule` is present (present=True) or absent (present=False)
    in the nftables ruleset for `container`.

    If `deadline` > 0, poll until the condition is met or the deadline (seconds)
    is reached, using `interval` between polls. If `deadline` == 0, perform a
    single immediate check.
    """
    end = time.time() + deadline if deadline and deadline > 0 else None

    while True:
        nft_out = run_command_in_container(container, ["nft", "list", "ruleset"])
        assert nft_out.returncode == 0, f"Failed to list nft ruleset: {nft_out.stderr}"
        found = core_rule in nft_out.stdout
        if present and found:
            return
        if not present and not found:
            return

        # Not in desired state yet
        if end is None or time.time() >= end:
            if present:
                raise AssertionError(f"Expected nft core rule not found in server ruleset.\nExpected core line:\n{core_rule}\nActual:\n{nft_out.stdout}")
            else:
                raise AssertionError(f"Expected nft core rule still present after timeout.\nCore line:\n{core_rule}\nActual:\n{nft_out.stdout}")

        time.sleep(interval)


def get_server_allowedip(loaded_config: dict) -> str:
    """Return the first AllowedIPs entry for the server peer from the loaded config.

    `loaded_config` is the dict returned by `api_get_config(...)`.
    This will raise KeyError if the expected keys are missing.
    """
    server_cfg = loaded_config["server"]
    # find server peer
    server_peer = None
    for p in loaded_config["peers"]:
        if p["name"] == server_cfg["name"]:
            server_peer = p
            break
    if server_peer is None:
        raise KeyError("Server peer not found in persisted config")

    parsed = parse_wg_section(server_peer["as_peer"])
    allowed = parsed["AllowedIPs"].split(",")[0].strip()
    return allowed


def _parse_address_from_config(cfg_text: str) -> str:
    for line in cfg_text.splitlines():
        if line.strip().startswith("Address"):
            # line like: Address = 10.0.0.2/32
            parts = line.split("=", 1)
            if len(parts) == 2:
                return parts[1].strip().split("/")[0]
    raise RuntimeError("Address not found in config")


@contextmanager
def wg_peer(docker_network: str, client_name: str, cfg_mod: str):
    """Context manager that starts a single wireguard client container,
    writes its config, brings up the interface, waits for establishment,
    and yields the container handle.
    """
    with run_container(
        "linuxserver/wireguard",
        name=client_name,
        network=docker_network,
        cap_add=["NET_ADMIN", "SYS_MODULE"],
        sysctls={"net.ipv4.conf.all.src_valid_mark": "1"},
    ) as cont:
        # Give container some time to settle
        time.sleep(5)

        # Write and bring up wg config on the client
        out = run_command_in_container(cont, ["sh", "-c", f"cat > /config/wg_confs/wg0.conf << 'EOF'\n{cfg_mod}\nEOF"])
        assert out.returncode == 0, f"Failed write config: {out.stderr}"

        out = run_command_in_container(cont, ["wg-quick", "up", "wg0"])
        assert out.returncode == 0, f"Failed wg-quick up: {out.stderr}"

        # Allow time for endpoints to establish
        time.sleep(4)

        yield cont


def get_container_logs(container):
    return container.logs(stdout=True, stderr=True, tail=1000).decode("utf-8", errors="replace")


def test_block_peer_to_peer_with_fw_rule(wg_slim_container, container_simple, docker_network, create_authenticated_session):
    server_ip = wg_slim_container.server_ip
    session = create_authenticated_session
    try:
        name_a = f"peer-a-{uuid.uuid4().hex[:6]}"
        name_b = f"peer-b-{uuid.uuid4().hex[:6]}"

        api_add_peer(session, container_simple, name_a)
        api_add_peer(session, container_simple, name_b)

        cfg_a = api_get_peer_config(session, container_simple, name_a)

        cfg_b = api_get_peer_config(session, container_simple, name_b)
        addr_b = _parse_address_from_config(cfg_b)

        def prepare_client_cfg(raw_cfg: str) -> str:
            cfg = re.sub(r"^Endpoint\s*=.*$", f"Endpoint = {server_ip}:51820", raw_cfg, flags=re.MULTILINE)
            cfg = re.sub(r"^AllowedIPs\s*=.*$", "AllowedIPs = 10.0.0.0/24", cfg, flags=re.MULTILINE)
            assert cfg != raw_cfg, "Client config modification failed"
            return cfg

        cfg_a_mod = prepare_client_cfg(cfg_a)
        cfg_b_mod = prepare_client_cfg(cfg_b)

        client_name_a = f"wg-client-a-{uuid.uuid4().hex[:8]}"
        client_name_b = f"wg-client-b-{uuid.uuid4().hex[:8]}"

        with wg_peer(docker_network, client_name_a, cfg_a_mod) as cont_a:
            with wg_peer(docker_network, client_name_b, cfg_b_mod) as _:
                ping = run_ping_check(cont_a, addr_b)
                assert ping.returncode == 0, f"Initial ping failed, stdout: {ping.stdout}\nstderr: {ping.stderr}"
                # Now set a fw_rules template via the API so the server persists it
                data = api_get_config(session, container_simple)
                rule = f"ip saddr {{{{AllowedIPs}}}} ip daddr {addr_b} drop;"
                template = f"""chain forward {{
                                type filter hook forward priority 0;
                                {rule}
                            }}
                """
                data["server"]["fw_rules"] = template
                api_put_config(session, container_simple, data)
                loaded = api_get_config(session, container_simple)
                allowed = get_server_allowedip(loaded)
                core_rule = f"ip saddr {allowed} ip daddr {addr_b} drop"
                check_nft_ruleset(wg_slim_container.container, core_rule)

                # Verify that ping stops working
                ping_res = run_ping_check(cont_a, addr_b, deadline=20, wait_for_fail=True)
                assert ping_res.returncode != 0, "Ping unexpectedly succeeded despite fw_rules blocking"

                del data["server"]["fw_rules"]

                api_put_config(session, container_simple, data)

                # Poll until nft no longer contains the expected rendered content
                check_nft_ruleset(wg_slim_container.container, core_rule, present=False, deadline=20)

                # Poll until ping succeeds again (connectivity restored)
                ping_res = run_ping_check(cont_a, addr_b, deadline=20)
                assert ping_res.returncode == 0, f"Ping did not succeed after removing fw_rules, last stdout: {getattr(ping_res, 'stdout', None)}"
    except AssertionError as e:
        server_logs = get_container_logs(wg_slim_container.container)
        print(f"Server container logs:\n{server_logs}")
        raise e
