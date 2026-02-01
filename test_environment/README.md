This test environment provides a simple Docker Compose setup to start the `wg-slim`
server (built from the repository root) and two peer containers.

Notes:
- The `wg-slim` service reads configuration from `/data/config.yaml`. The compose file
  mounts the `test_environment/config.yaml` into that path.
- The peer containers (`peer1` and `peer2`) are lightweight `alpine` containers that
  mount placeholder peer configs at `/peer/peer.conf` and simply sleep. They are
  intended as stand-ins for real WireGuard peers for smoke testing startup.

To start the environment:

```bash
cd test_environment
docker-compose up --build -d
This test environment provides a Docker Compose setup to start the `wg-slim`
server (built from the repository root) and two WireGuard-capable peer containers.

Notes:
- The `wg-slim` service reads configuration from `/data/config.yaml`. The compose file
  mounts `test_environment/config_primary.yaml` into that path and exposes the web UI on port `8000`.
- `wg-slim` is configured to be the WireGuard server in this environment. The container
  is started with elevated capabilities so it can create the WireGuard interface and bind
  to UDP port `51820`.
- The `peer1` and `peer2` containers are full WireGuard-capable images that:
  - authenticate to the `wg-slim` API using the admin password from `config.yaml`,
  - request their generated peer config from `/api/peers/<name>/config`,
  - write it to `/etc/wireguard/wg0.conf`, and
  - run `wg-quick up /etc/wireguard/wg0.conf` to bring the interface up.

To start the environment:

```bash
cd test_environment
docker-compose up --build -d
```

To stop and remove:

```bash
docker-compose down
```

Caveats:
- This setup runs containers with elevated privileges (`privileged` and `NET_ADMIN`) and
  uses kernel WireGuard support. It may require Docker to run with permissions that are
  not available in all CI environments.
- If you prefer `wg-slim` to manage host-level WireGuard interfaces (outside containers),
  run the app on the host with appropriate permissions instead of in Docker.

If you want me to also:
- add a small health-check or a script that verifies peers are connected,
- or switch `wg-slim` to run on the host network instead of container network,
let me know which option you prefer.
