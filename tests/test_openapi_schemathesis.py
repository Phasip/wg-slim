import os
from typing import Dict
from fastapi.testclient import TestClient
from schemathesis import Case

from hypothesis import strategies as st
import pytest
import schemathesis
import yaml

import wg_api as auth_jwt

SCHEMA_PATH: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "openapi.yaml"))
config_path: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_environment", "config_primary.yaml"))
with open(config_path, "r", encoding="utf-8") as fh:
    fullconf_text: str = fh.read()
    parsed: Dict[str, object] = yaml.safe_load(fullconf_text)

yaml_fullconf_examples: list[str] = [fullconf_text]
yaml_server_examples: list[str] = [yaml.safe_dump(parsed["server"])]
yaml_peer_examples: list[str] = [yaml.safe_dump(parsed["peers"][0])]  # type: ignore
wgconf_examples: list[str] = [
    """[Interface]
Address = 10.0.0.1/24
PrivateKey = SC64mx9MKXmUrcZown1nnQHmIOJLQP8N7S6MDTJ1JUk=
[Peer]
PublicKey = qzwoE3M1fdGOhu0fsBlWxGNE/OQcwo7HWOnURjjXYUs=
AllowedIPs = 10.0.0.2/32
""",
]

schemathesis.openapi.format("yaml-fullconf", st.sampled_from(yaml_fullconf_examples))
schemathesis.openapi.format("yaml-server", st.sampled_from(yaml_server_examples))
schemathesis.openapi.format("yaml-peer", st.sampled_from(yaml_peer_examples))
schemathesis.openapi.format("wgconf", st.sampled_from(wgconf_examples))


@pytest.fixture
def api_schema(unauth_api_client: TestClient):
    schema = schemathesis.openapi.from_path(SCHEMA_PATH)
    schema.config.base_url = "http://127.0.0.1/api"
    schema.app = unauth_api_client.app
    return schema


@pytest.fixture
def asgi_api_schema(api_client: TestClient):
    schema = schemathesis.openapi.from_asgi(app=api_client.app, path="/openapi.json")
    schema.config.base_url = "http://127.0.0.1"
    schema.app = api_client.app
    return schema


schema = schemathesis.pytest.from_fixture("api_schema")


@schemathesis.auth()
class SchemathesisAuth:
    def get(self, case: Case, ctx: schemathesis.AuthContext) -> str:
        """Return an access token for the test app."""
        return auth_jwt.create_access_token(app=ctx.app)

    def set(self, case: Case, data: str, ctx: schemathesis.AuthContext) -> None:
        case.headers["Authorization"] = f"Bearer {data}"


@schema.parametrize()
def test_api_routes_exist(case: Case, unauth_api_client: TestClient, mock_wg_manager) -> None:
    """Run each schemathesis case against the app and validate the response."""
    excluded_checks = []
    if case.operation.path == "/settings/password" and case.operation.method == "put":
        if case.body and isinstance(case.body, dict) and "new_password" in case.body:
            case.body["confirm_password"] = case.body["new_password"]

    response = case.call(app=unauth_api_client.app)
    case.validate_response(response, excluded_checks=excluded_checks)
