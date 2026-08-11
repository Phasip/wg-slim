#!/usr/bin/env python3
"""Container healthcheck: ask the local API whether it is healthy.

Reads the configured `bind_addr` so the check keeps working when the port is
changed, and deliberately imports nothing from the application itself - a
healthcheck must not depend on the app being importable.
"""

import json
import os
import sys
import urllib.request

import yaml

import wg_utils

CONFIG_FILE = os.environ.get("CONFIG_FILE", "/data/config.yaml")
TIMEOUT_SECONDS = 5


def check() -> bool:
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    host, port = wg_utils.parse_bind_addr(str(data["basic"]["bind_addr"]))
    # A wildcard bind is not a usable destination address.
    if host in ("0.0.0.0", "::", ""):
        host = "127.0.0.1"

    with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=TIMEOUT_SECONDS) as response:
        if response.status != 200:
            return False
        payload = json.load(response)

    return payload.get("status") == "healthy"


if __name__ == "__main__":
    sys.exit(0 if check() else 1)
