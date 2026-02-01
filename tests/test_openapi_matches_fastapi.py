import os

import pytest
import yaml

SCHEMA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "openapi.yaml"))


def test_no_undocumented_api_routes(unauth_api_client):
    """Ensure every API route under the `/api` prefix is documented
    in `openapi.yaml`, and that every documented path exists on the app.

    This version assumes a FastAPI/Starlette app (inspects `app.routes`).
    """
    with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    documented_paths = set(spec["paths"].keys())
    actual_paths: set[str] = set()

    for route in unauth_api_client.app.routes:
        if not route.path or not route.path.startswith("/api"):
            continue
        actual_paths.add(route.path[len("/api") :])

    assert len(actual_paths) != 0
    assert len(documented_paths) != 0
    undocumented = actual_paths - documented_paths
    missing = documented_paths - actual_paths
    msgs: list[str] = []
    if undocumented:
        msgs.append(f"Undocumented routes present in app: {undocumented}")
    if missing:
        msgs.append(f"Documented paths missing from app: {missing}")

    if msgs:
        pytest.fail("; ".join(msgs))
