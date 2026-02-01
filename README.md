# wg-slim

# STATUS
- Alpha quality software. Runs fine for me but probably has bugs.


# Description
Dockerized wireguard with web-ui. Specification-first, API endpoints generated from `openapi.yaml` specification.

Made to be super-simple to setup while exposing full configurability of wireguard.

<img width="1013" height="668" alt="image" src="https://github.com/user-attachments/assets/8e4675d7-3162-42a5-b398-c4ab1ca7cc57" />


## Quick Start
Access the web UI at http://localhost:5000
Default password: password (set via `INITIAL_CONFIG` environment variable — provide the initial config as YAML text)
```bash
docker build -t wg-slim:latest .
docker-compose -f examples/docker-compose.basic.yml up -d
```

The server and each peer has two sections, "inteface" and "as_peer". The "interface" section configures [Interface] section for that users config. The "as_peer" section configures "[Peer]" section that will be seen in other configs.

## PreSharedKey (PSK) handling
wg-slim supports PSK configuration with some caveats.
Each peer, including server, can only have one PSK defined.

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
| `INITIAL_CONFIG` | `basic:\n  password: password\n  bind_addr: "5000"\nserver:\n  interface_name: wg0` | Initial config as YAML text (used if no config file exists) |
| `CONFIG_FILE` | `/data/config.yaml` | Configuration file path |

Note: Config file will be generated if not existing, thus INITIAL_CONFIG is only relevant at first run.

## Files
Docker compose example: `examples/docker-compose.basic.yml`
Test environment with server and one peer: `test_environment/`
Converter scripts (for migration): `converters/`

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
# Generate OpenAPI server and clients
make openapi-server
make openapi-client
make openapi-python-client

# Install generated Python packages in editable mode (required for development)
pip install -e openapi_generated/python-fastapi
pip install -e openapi_generated/python-client --config-settings editable_mode=compat
```

Note: The generated `openapi_server` and `wgslim_api_client` packages must be installed in editable mode to be importable in your Python code. The `--config-settings editable_mode=compat` flag ensures pyright can resolve the types (uses legacy path-based editable install instead of PEP 660 finder). In production (Docker), these are installed automatically during the build process.

### 3. Run tests

```bash
# Run full test suite
make test
```

### Full test in docker (only docker required)
```bash
make test-docker
```


# Security
## Pros
- Strict HTTP headers
- Timing attack resistant password and token comparison
- No cookies, only bearer tokens in Authorization header
- Specification first API design with auto-generated server routes enforicing input format and authentication
- Lots of tests to counter horrible AI coding
- Low attack surface (no databases, only local bootstrap in frontend, minimal dependencies)
## Cons
- Plaintext password in config and no pw policies (it's a feature!)
- Command injection through PostUp/PostDown (it's a feature!)
- No rate limiting or brute-force protection
- No HTTPS (Expose only internally or use some other container for that I guess)
- All private keys stored unencrypted and fully accessible to anyone with the password.


# Known issues
- Test sometimes leaves broken state files, delete /tmp/wg-slim-*.lock to undo
- Some tests randomly fail due to timing issues (TODO)
- Port change has no effect until restart (TODO?)


TODO:
- How to handle mesh of servers?
- Some issue with PSK when multiple peers with endpoints
- Maybe let peers request their own WG.conf using their private key.
