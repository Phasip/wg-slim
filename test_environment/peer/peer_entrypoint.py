#!/usr/bin/env python3

import requests
import subprocess
import os
import time

# Minimal hard-coded values
PEER_NAME = "peer1"
WG_SLIM_URL = "http://wg-slim:5000"
PASSWORD = "testpassword"

print("Peer entrypoint starting")

s = requests.Session()
for _ in range(10):
    try:
        s.get(WG_SLIM_URL + "/api/health")
        break
    except requests.exceptions.RequestException:
        time.sleep(10)
else:
    print("Failed to connect to wg-slim")
    exit(1)

resp = s.post(WG_SLIM_URL + "/api/login", json={"password": PASSWORD})
print("Login response:", resp.status_code)
token = resp.json().get("access_token")
if not token:
    print("Failed to get access token")
    exit(1)
s.headers.update({"Authorization": f"Bearer {token}"})
cfg_url = f"{WG_SLIM_URL}/api/peers/{PEER_NAME}/config"
resp = s.get(cfg_url)
obj = resp.json()
print("Got peer config:", obj)
if "error" in obj:
    print("Error getting peer config:", obj["error"])
    exit(1)
config_text = obj["config"]

os.makedirs("/etc/wireguard", exist_ok=True)
path = "/etc/wireguard/wg0.conf"
open(path, "w").write(config_text)

subprocess.run(["wg-quick", "up", path], check=True)

print("WireGuard up; sleeping")
while True:
    time.sleep(60)
    subprocess.run(["wg", "show"], check=False)
