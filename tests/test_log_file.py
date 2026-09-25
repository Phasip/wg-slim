"""Tests for the log file behind `/api/server/logs`."""

import logging
import os
import stat

import wg_api
import wg_openapi_impl
import wg_utils


def log_path(unauth_api_client):
    return wg_utils.log_file_path(unauth_api_client.app.state.config_manager.file_path)


def auth(client):
    token = client.post("/api/login", json={"password": "testpassword"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_create_app_does_not_stack_log_handlers(unauth_api_client, config_for_test_client):
    wg_api.create_app(config_file=config_for_test_client, sync_service=unauth_api_client.app.state.sync_service)
    wg_api.create_app(config_file=config_for_test_client, sync_service=unauth_api_client.app.state.sync_service)
    installed = [h for h in logging.getLogger().handlers if type(h) is wg_api.PrivateRotatingFileHandler]
    assert len(installed) == 1


def test_rotated_log_files_are_private(unauth_api_client):
    handler = unauth_api_client.app.state.log_handler
    handler.doRollover()
    for path in (handler.baseFilename, handler.baseFilename + ".1"):
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_logs_endpoint_returns_only_the_tail(unauth_api_client):
    headers = auth(unauth_api_client)
    with open(log_path(unauth_api_client), "w", encoding="utf-8") as f:
        for i in range(wg_openapi_impl.LOG_TAIL_LINES + 50):
            f.write(f"line {i}\n")
    logs = unauth_api_client.get("/api/server/logs", headers=headers).json()["logs"]
    assert len(logs) == wg_openapi_impl.LOG_TAIL_LINES
    assert logs[-1] == f"line {wg_openapi_impl.LOG_TAIL_LINES + 49}"


def test_clearing_logs_removes_rotated_file(unauth_api_client):
    handler = unauth_api_client.app.state.log_handler
    headers = auth(unauth_api_client)
    handler.doRollover()
    assert os.path.exists(handler.baseFilename + ".1")
    assert unauth_api_client.delete("/api/server/logs", headers=headers).status_code == 200
    assert not os.path.exists(handler.baseFilename + ".1")
