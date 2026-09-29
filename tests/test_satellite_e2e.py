"""Live end-to-end tests for satellite domains over a real sync channel.

A real uvicorn server plays the remote (its sync WebSocket fed from the
process-global database), while the satellite side runs through the ASGI
app with a real RemoteReplica started by the real SatelliteManager
reconcile. Unlike test_remote.py (which injects a warm replica by hand),
nothing here is stubbed: the snapshot, live events, write-behind, dead-peer
TTL handling and reconnect reconciliation all cross a TCP socket.

One in-process distortion remains: both sides share the module-level
database and registry, so endpoints the satellite *forwards* to the remote
(logout, set-session, OIDC) would re-forward and loop here — those paths
are covered in test_remote.py with a mocked forward_request.
"""

import asyncio
import socket
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
import pytest_asyncio
import uvicorn

import paskia.db.operations as ops_db
from paskia import domains, satellite
from paskia.db.structs import Config, DomainConfig, OriginEntry, RemoteConfig
from paskia.fastapi.mainapp import app
from paskia.fastapi.session import AUTH_COOKIE_NAME

from .conftest import TEST_RP_ID, create_test_session

REMOTE_DOMAIN = "example.com"
APP_HOST = "app2.example.com"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def wait_for(desc: str, condition, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"timed out waiting for {desc}")


@pytest_asyncio.fixture
async def live_remote(test_db, monkeypatch):
    """A uvicorn-served 'remote' and the satellite manager wired against it.

    The manager is started for real: reconcile builds the replica from the
    domain config and its sync client connects over TCP. Yielded namespace:
    client (ASGI, satellite side), replica, db (the remote's database),
    url/port of the remote, start_server (for restarts), servers.
    """
    monkeypatch.setenv("PASKIA_SYNC_TOKENS", "live-tok")
    servers: list[tuple[uvicorn.Server, asyncio.Task]] = []

    async def start_server(port: int) -> uvicorn.Server:
        config = uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error", lifespan="off"
        )
        server = uvicorn.Server(config)
        task = asyncio.create_task(server.serve())
        servers.append((server, task))
        while not server.started:
            await asyncio.sleep(0.02)
        return server

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    await start_server(port)

    domains.configure(listen=["localhost:4401"])
    domains.init_registry(
        Config(
            domains={
                TEST_RP_ID: DomainConfig(origins={f"**.{TEST_RP_ID}": True}),
                REMOTE_DOMAIN: DomainConfig(
                    origins={
                        f"**.{REMOTE_DOMAIN}": True,
                        f"auth.{REMOTE_DOMAIN}": OriginEntry(auth_host=True),
                    },
                    remote=RemoteConfig(url=url, token="live-tok"),
                ),
            }
        )
    )
    await satellite.manager.start()
    replica = satellite.manager.replicas[url]
    await wait_for("initial snapshot", lambda: replica.available())

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:4401"
    ) as client:
        try:
            yield SimpleNamespace(
                client=client,
                replica=replica,
                db=test_db,
                url=url,
                port=port,
                start_server=start_server,
                servers=servers,
            )
        finally:
            await satellite.manager.stop()
            for server, task in servers:
                server.should_exit = True
                await task


def _app_headers(secret: str) -> dict[str, str]:
    return {"Host": APP_HOST, "Cookie": f"{AUTH_COOKIE_NAME}={secret}"}


@pytest.mark.asyncio
async def test_live_snapshot_and_user_events(live_remote, test_user):
    """Bootstrap data arrives with the snapshot; later mutations as events."""
    assert test_user.uuid in live_remote.replica.db.users
    ops_db.update_user_display_name(test_user.uuid, "Live Rename")
    await wait_for(
        "rename to propagate",
        lambda: (
            live_remote.replica.db.users[test_user.uuid].display_name == "Live Rename"
        ),
    )


@pytest.mark.asyncio
async def test_live_forward_and_writebehind(live_remote, test_user, test_credential):
    """A session created on the remote authorizes locally; the /validate
    refresh travels back over the wire into the remote's database."""
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for("session sync", lambda: key in live.replica.db.sessions)

    r = await live.client.get(
        "/auth/api/forward?perm=auth:admin", headers=_app_headers(secret)
    )
    assert r.status_code == 204
    assert r.headers["remote-name"] == "Test Admin"

    # Age the session on the remote (propagates), then validate on the satellite
    stale = datetime.now(UTC) - timedelta(minutes=10)
    ops_db.update_session(key, validated=stale)
    await wait_for(
        "staleness to propagate",
        lambda: live.replica.db.sessions[key].validated == stale,
    )
    r = await live.client.post("/auth/api/validate", headers=_app_headers(secret))
    assert r.status_code == 200
    assert r.json()["renewed"] is True
    await wait_for(
        "write-behind to land on the remote",
        lambda: live.db.sessions[key].validated > stale,
    )


@pytest.mark.asyncio
async def test_live_session_delete_propagates(live_remote, test_user, test_credential):
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for("session sync", lambda: key in live.replica.db.sessions)

    ops_db.delete_session(key)
    await wait_for(
        "session delete to propagate", lambda: key not in live.replica.db.sessions
    )
    r = await live.client.get("/auth/api/forward", headers=_app_headers(secret))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_live_wrong_token_rejected(live_remote):
    bad = satellite.RemoteReplica(RemoteConfig(url=live_remote.url, token="wrong"))
    await bad.start()
    try:
        await asyncio.sleep(1.5)
        assert not bad.available()
    finally:
        await bad.stop()


@pytest.mark.asyncio
async def test_live_disconnect_ttl_and_reconnect(
    live_remote, test_user, test_credential
):
    """Channel down: replica keeps serving within cache_ttl, then fails
    closed (503); reconnect starts from a snapshot and reconciles drift."""
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for("session sync", lambda: key in live.replica.db.sessions)

    server, task = live.servers[0]
    server.should_exit = True
    await task
    await wait_for(
        "dead peer detection", lambda: not live.replica.connected, timeout=15
    )

    r = await live.client.get("/auth/api/forward", headers=_app_headers(secret))
    assert r.status_code == 204  # still authoritative within cache_ttl

    live.replica.remote.cache_ttl = 0  # expire the trust window
    r = await live.client.get("/auth/api/forward", headers=_app_headers(secret))
    assert r.status_code == 503

    # Drift while the channel is down, then let the client auto-reconnect
    ops_db.update_user_display_name(test_user.uuid, "While Down")
    await live.start_server(live.port)
    await wait_for("reconnect", lambda: live.replica.available(), timeout=20)
    assert (
        live.replica.db.users[test_user.uuid].display_name == "While Down"
    )  # snapshot reconciled the drift
    r = await live.client.get("/auth/api/forward", headers=_app_headers(secret))
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_reconcile_stops_replica_when_remote_removed(live_remote):
    """A registry rebuild without the remote config stops the replica."""
    live = live_remote
    domains.init_registry(
        Config(domains={TEST_RP_ID: DomainConfig(origins={f"**.{TEST_RP_ID}": True})})
    )
    await wait_for(
        "replica shutdown", lambda: live.url not in satellite.manager.replicas
    )
