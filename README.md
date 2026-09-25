# wg-slim

## STATUS

- Alpha quality software. Runs fine for me but probably has bugs.

## Description

Dockerized wireguard with web-ui. Specification-first, API endpoints generated from `openapi.yaml` specification.

Made to be super-simple to setup while exposing full configurability of wireguard.

<img width="1157" height="730" alt="screenshot" src="https://github.com/user-attachments/assets/e695e841-96ae-4527-bef7-6b04d2fd3932" />

## Quick Start

Access the web UI at http://localhost:5000

If no password is set via the `INITIAL_CONFIG` environment variable a new password is generated and output to stdout on first run.

```bash
$ docker compose -f examples/docker-compose.basic.yml up -d
$ docker compose -f examples/docker-compose.basic.yml logs | grep password
wg-slim_1  | First setup, no initial password provided.
wg-slim_1  | Web management password: SqxEyHToOYkvALVk
```

### Hashed password

Instead of `basic.password` you can set `basic.password_hash` (setting both is an error). Generate the hash with:

```bash
$ docker compose -f examples/docker-compose.basic.yml exec wg-slim python3 wgslim_cli.py hash-password
Password:
Repeat password:
scrypt$16384$8$1$...
```

Put the printed value in `INITIAL_CONFIG` or the config file:

```yaml
basic:
  bind_addr: "5000"
  password_hash: "scrypt$16384$8$1$..."
```

When a hash is configured, changing the password in the web UI stores a new hash, not a plaintext password.

## Configuration

The server and each peer has two sections, "inteface" and "as_peer". The "interface" section configures [Interface] section for that users config. The "as_peer" section configures "[Peer]" section that will be seen in other configs.

Two rules are enforced on every save, and a config violating either is rejected with a 400: peer names must be unique, and one peer must be named after `server.name` (that peer holds the server's own interface). Renaming the server peer therefore fails — change `server.name` and the peer name together in the config editor.

## PreSharedKey (PSK) handling

wg-slim supports PSK configuration with some caveats. Each peer, including server, can only have one PSK defined.

Allowing more flexible PSK configuration could not be motivated due to increasing complexity or cause portability issues.

PSK selection rules:

- **Client-to-Server**: Uses the client's PSK first, if not defined uses server's PSK
- **Server-to-Server**: Uses either server's PSK (warns if they differ)
- **Client-to-Client**: Not applicable (clients don't connect to each other)

Note: Server = Peer with endpoint defined, Client = Peer without endpoint defined.

TODO: Reason whether unique PSK-seeds should be implemented that are used to generated unique PSKs for each peer pair.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `INITIAL_CONFIG` | `basic:\n  bind_addr: "5000"\nserver:\n  interface_name: wg0` | Initial config as YAML text (used if no config file exists) |
| `CONFIG_FILE` | `/data/config.yaml` | Configuration file path |

Note: Config file will be generated if not existing, thus INITIAL_CONFIG is only relevant at first run.

## Files

Docker compose example: `examples/docker-compose.basic.yml`

Test environment with server and one peer: `test_environment/`

Converter scripts (for migration from other systems): `converters/`

- `converters/from_wgeasy_old.py` — wg-easy `wg0.json` importer (covered by `tests/test_converter_wgeasy.py`, output is validated against the `WireGuardConfig` schema in `openapi.yaml`):

  ```bash
  python converters/from_wgeasy_old.py wg0.json vpn.example.com:51820 [password] \
      [--server-prefix 24] [--dns 1.1.1.1] [--mtu 1420] [--interface-name wg0] \
      [--client-allowed-ips 0.0.0.0/0] > config.yaml
  ```

  Client names are sanitized to the peer name rules (`^[A-Za-z0-9_-]{1,64}$`) and de-duplicated. A per-client `allowedIPs` field (used by wg-easy forks for site-to-site peers) is appended to that peer's `as_peer` AllowedIPs after its own `/32`, i.e. it is read as "networks routed *to* this peer".

- Plain `wg0.conf` import is built into the API — no script needed. `POST /api/config/import-wg` with the file contents and an endpoint, or use the "Import" action in the web UI. It is only accepted while the config still has just the server peer.

- `converters/from_wgeasy_sqlite.py` — wg-easy sqlite importer. Note: untested and probably broken.

## Development

### 1. Setup dependencies

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
pip install -r requirements-build.txt
```

### 2. Generate and install openapi.yaml dependent code

```bash
# Generate the OpenAPI server and clients, then install the Python packages
make openapi
make install-generated
```

Note: The generated `openapi_server` and `wgslim_api_client` packages must be installed to be importable in your Python code; `make install-generated` does that. Rerun it after regenerating. Codegen is skipped when `openapi.yaml` has not changed since the last run — use `make openapi-clean openapi` to force a full rebuild. In production (Docker), all of this happens during the build.

### 3. Run tests

```bash
# Run full test suite
make test
```

### Full test in docker (only docker required)

```bash
make test-docker
```

## Security

### Pros

- Strict HTTP headers
- Timing attack resistant password and token comparison
- Failed logins are throttled per client address (5 per 5 minutes). Behind a reverse proxy, set `FORWARDED_ALLOW_IPS` to the proxy's address so the real client address is used
- No cookies, only bearer tokens in Authorization header
- Changing the password revokes every other session (the caller keeps its own)
- Config is written atomically and always as 0600 (it holds every private key)
- YAML submitted through the API may not use aliases (blocks alias-expansion bombs)
- Specification first API design with auto-generated server routes enforicing input format and authentication
- Lots of tests to counter horrible AI coding
- Low attack surface (no databases, only local bootstrap in frontend, minimal dependencies)

### Cons

- Plaintext password in config and no pw policies (it's a feature!)
- Command injection through PostUp/PostDown (it's a feature!)
- No HTTPS (Expose only internally or use some other container for that I guess)
- All private keys stored unencrypted and fully accessible to anyone with the password.

## Known issues

- Test sometimes leaves broken state files, delete /tmp/wg-slim-*.lock to undo
- Some tests randomly fail due to timing issues (TODO)
- Port change has no effect until restart (TODO?)

## TODO

- How to handle mesh of servers?
- Some issue with PSK when multiple peers with endpoints
- Maybe let peers request their own WG.conf using their private key.
