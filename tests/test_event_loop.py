"""Blocking handler work must not stall the event loop."""

import asyncio
import threading

import httpx


def test_slow_sync_does_not_block_health(unauth_api_client):
    app = unauth_api_client.app
    release = threading.Event()
    # Registered after the startup watchers, so it runs on every save.
    app.state.config_manager.add_on_config_change(lambda: release.wait(5))

    async def scenario():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            token = (await client.post("/api/login", json={"password": "testpassword"})).json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            slow = asyncio.create_task(client.post("/api/peers/peer1/disable", headers=headers))
            await asyncio.sleep(0.1)
            health = await asyncio.wait_for(client.get("/api/health"), timeout=2)
            assert not slow.done(), "the save should still be blocked in its watcher"
            release.set()
            return health, await slow

    health, slow = asyncio.run(scenario())
    assert health.status_code == 200
    assert slow.status_code == 200
