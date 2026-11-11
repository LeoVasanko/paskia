"""Live end-to-end tests for satellite domains over a real sync channel.

A real uvicorn server plays the upstream (its sync WebSocket fed from the
process-global database), while the satellite side runs through the ASGI
app with a real UplinkReplica started by the real SatelliteManager. Unlike
test_remote.py (which injects a warm replica by hand), nothing here is
stubbed: the quantumpipe handshake, pushed domains, snapshot, live events,
write-behind, dead-peer TTL handling, reconnect reconciliation, live scope
changes and revocation all cross a TCP socket.

One in-process distortion remains: both sides share the module-level
database and registry, so the satellite's pushed-domain application is
arranged to be a no-op (the link's domains are absent from the shared
config — the satellite registry is synthetic instead), and endpoints the
satellite *forwards* to the upstream (logout, set-session, OIDC) would
re-forward and loop here — those paths are covered in test_remote.py with
a mocked forward_request.
"""

import asyncio
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

import httpx
import msgspec.structs
import pytest
import pytest_asyncio
import uvicorn
from kanta import Kanta
from quantumpipe import Session, generate_registration_secret

import paskia.db.operations as ops_db
from paskia import domains, satellite
from paskia.db.structs import (
    DB,
    Config,
    Credential,
    DomainConfig,
    OriginEntry,
    RemoteConfig,
    Uplink,
)
from paskia.fastapi import sync
from paskia.fastapi.mainapp import app
from paskia.fastapi.session import AUTH_COOKIE_NAME

from .conftest import TEST_RP_ID, create_test_session

REMOTE_DOMAIN = "example.com"
APP_HOST = "app2.example.com"
LINK_ID = "live-link"


def _link_credentials() -> tuple[bytes, bytes]:
    secret = generate_registration_secret()
    server_store = {LINK_ID: secret}
    client_store = {LINK_ID: secret}
    server = Session(server_store)
    client = Session(client_store, LINK_ID)
    (msg1,) = client()
    (msg2,) = server(msg1)
    (msg3,) = client(msg2)
    (verification,) = server(msg3)
    (msg4,) = server(verification)
    (verification,) = client(msg4)
    msg5, _ = client(verification)
    server(msg5)
    return server.credential, client.credential


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
async def live_server(test_db):
    """A uvicorn-served upstream over a real TCP socket.

    Yields a namespace: db, url, port, start_server (for restarts),
    servers.
    """
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
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(test_db.config)
    await start_server(port)
    try:
        yield SimpleNamespace(
            db=test_db, url=url, port=port, start_server=start_server, servers=servers
        )
    finally:
        for server, task in servers:
            server.should_exit = True
            await task


@pytest_asyncio.fixture
async def live_remote(live_server):
    """An established encrypted link with a real replica and sync feed.

    Both sides' link rows are stored directly (registration itself is
    covered by the dedicated tests); the satellite's remote domain lives
    only in the registry, not the shared config, so pushed-domain
    application stays a no-op.
    """
    live = live_server
    server_key, client_key = _link_credentials()
    ops_db.create_satellite_link(LINK_ID, [REMOTE_DOMAIN], server_key, label="e2e")
    uplink = Uplink(url=live.url, created=datetime.now(UTC), key=client_key)
    ops_db.create_uplink(LINK_ID, uplink, {})

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
                    remote=RemoteConfig(link=LINK_ID),
                ),
            }
        )
    )
    await satellite.manager.start()
    replica = satellite.manager.replicas[LINK_ID]
    await wait_for("initial snapshot", lambda: replica.available())

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:4401"
    ) as client:
        try:
            live.client = client
            live.replica = replica
            yield live
        finally:
            await satellite.manager.stop()


def _app_headers(secret: str) -> dict[str, str]:
    return {"Host": APP_HOST, "Cookie": f"{AUTH_COOKIE_NAME}={secret}"}


@pytest_asyncio.fixture
async def remote_credential(test_db, test_user):
    """A credential registered on the remote domain. The feed is rp-id
    scoped: only the link's own domains' credentials replicate."""
    credential = Credential.create(
        credential_id=os.urandom(32),
        user=test_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
        rp_id=REMOTE_DOMAIN,
    )
    ops_db.create_credential(credential)
    return credential


# -------------------------------------------------------------------------
# Registration (the real quantumpipe exchange, crossing TCP)
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_registration(live_server):
    """A RAM-only offer is spent; both sides persist working credentials."""
    live = live_server
    offer_url = sync.create_offer([], live.url)
    assert offer_url.startswith("ws://")

    result = await satellite.register_uplink(offer_url)
    link_id = result["link"]
    assert result["domains"] == []  # empty scope: register first, scope later

    uplink = live.db.uplinks[link_id]
    assert uplink.url == live.url
    link = live.db.satellite_links[link_id]
    assert len(uplink.key) == len(link.key) > 32
    assert uplink.key != link.key  # each side has its own private identity root
    assert link.label  # the satellite's self-reported name

    # Re-registering to the same upstream is refused (the offer itself is
    # single-use — covered in test_remote.py's offer test)
    with pytest.raises(ValueError, match="Already linked"):
        await satellite.register_uplink(offer_url)

    # The established-link handshake: the replica connects and syncs
    await satellite.manager.start()
    try:
        replica = satellite.manager.replicas[link_id]
        await wait_for("established link sync", lambda: replica.available())
    finally:
        await satellite.manager.stop()


@pytest.mark.asyncio
async def test_live_registration_rejections(live_server):
    """Malformed URLs, unknown keys and unreachable hosts store nothing."""
    secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    with pytest.raises(ValueError, match="wss"):
        await satellite.register_uplink("https://key@auth.example.com")
    with pytest.raises(ValueError, match="key"):
        await satellite.register_uplink("wss://auth.example.com")
    with pytest.raises(RuntimeError, match="rejected"):
        await satellite.register_uplink(
            f"ws://unknown:{secret}@127.0.0.1:{live_server.port}"
        )
    with pytest.raises(RuntimeError, match="unreachable"):
        await satellite.register_uplink(f"ws://some:{secret}@127.0.0.1:1")
    assert not live_server.db.uplinks
    assert not live_server.db.satellite_links


@pytest.mark.asyncio
async def test_cli_satellite_command(live_server, tmp_path):
    """The whole satellite-only setup, two processes: the CLI registers
    against the live upstream (creating its own database on the way) and
    stores the link and the pushed domains — 'paskia' then serves them."""
    live = live_server
    ops_db.create_domain(
        REMOTE_DOMAIN,
        DomainConfig(
            rp_name="Example",
            origins={
                f"**.{REMOTE_DOMAIN}": True,
                f"auth.{REMOTE_DOMAIN}": OriginEntry(auth_host=True),
            },
        ),
    )
    offer_url = sync.create_offer([REMOTE_DOMAIN], live.url)
    proc = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-m", "paskia", "satellite", offer_url],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={k: v for k, v in os.environ.items() if not k.startswith("PASKIA_")},
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert REMOTE_DOMAIN in proc.stdout

    # The satellite's own database holds the uplink and the pushed domain.
    sat_db_path = tmp_path / "paskia.kantadb"
    kanta = Kanta(str(sat_db_path), DB())
    await kanta.open(readonly=True)
    try:
        sat_domains = dict(kanta.data.config.domains)
        uplinks = dict(kanta.data.uplinks)
    finally:
        await kanta.close()
    domain = sat_domains[REMOTE_DOMAIN]
    assert domain.remote is not None
    assert domain.rp_name == "Example"
    ((link_id, uplink),) = uplinks.items()
    assert uplink.url == live.url
    assert len(live.db.satellite_links[link_id].key) == len(uplink.key) > 32
    assert live.db.satellite_links[link_id].rp_ids == [REMOTE_DOMAIN]


# -------------------------------------------------------------------------
# Established link: sync behavior
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_snapshot_and_context_repush(
    live_remote, test_user, remote_credential
):
    """Sessions arrive with their upstream-computed context; user-graph
    changes eagerly re-push the affected sessions' contexts."""
    live = live_remote
    key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for("session sync", lambda: key in live.replica.db.session_contexts)
    assert live.replica.db.session_contexts[key].user.display_name == "Test Admin"

    ops_db.update_user_display_name(test_user.uuid, "Live Rename")
    await wait_for(
        "rename to propagate",
        lambda: (
            live.replica.db.session_contexts[key].user.display_name == "Live Rename"
        ),
    )


@pytest.mark.asyncio
async def test_live_permission_revocation_propagates(
    live_remote, test_user, remote_credential
):
    """Removing a permission from the user's role re-pushes the session
    context: the satellite denies within one RTT."""
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for("session sync", lambda: key in live.replica.db.session_contexts)
    r = await live.client.get(
        "/auth/api/forward?perm=auth:admin", headers=_app_headers(secret)
    )
    assert r.status_code == 204

    perm_uuid = next(
        p.uuid for p in live.db.permissions.values() if p.scope == "auth:admin"
    )
    ops_db.remove_permission_from_role(test_user.role_uuid, perm_uuid)
    await wait_for(
        "revocation to propagate",
        lambda: "auth:admin" not in live.replica.db.session_contexts[key].permissions,
    )
    r = await live.client.get(
        "/auth/api/forward?perm=auth:admin", headers=_app_headers(secret)
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_live_forward_and_writebehind(live_remote, test_user, remote_credential):
    """A session created on the upstream authorizes locally; the /validate
    refresh travels back over the wire into the upstream's database."""
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for("session sync", lambda: key in live.replica.db.sessions)

    r = await live.client.get(
        "/auth/api/forward?perm=auth:admin", headers=_app_headers(secret)
    )
    assert r.status_code == 204
    assert r.headers["remote-name"] == "Test Admin"

    # Age the session on the upstream (propagates), then validate on the satellite
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
        "write-behind to land on the upstream",
        lambda: live.db.sessions[key].validated > stale,
    )


@pytest.mark.asyncio
async def test_live_session_delete_propagates(
    live_remote, test_user, remote_credential
):
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
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
async def test_live_wrong_key_rejected(live_remote):
    """An uplink whose key does not match the stored link's never syncs."""
    uplink = Uplink(url=live_remote.url, created=datetime.now(UTC), key=b"not-the-key")
    uplink.uplink_id = "bad-link"
    bad = satellite.UplinkReplica(uplink)
    await bad.start()
    try:
        await asyncio.sleep(1.5)
        assert not bad.available()
    finally:
        await bad.stop()


@pytest.mark.asyncio
async def test_live_disconnect_ttl_and_reconnect(
    live_remote, test_user, remote_credential
):
    """Channel down: replica keeps serving within cache_ttl, then fails
    closed (503); reconnect starts from a snapshot and reconciles drift."""
    live = live_remote
    key, secret = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
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

    # Expire the trust window (a copy: the db-owned struct is not mutated)
    uplink_copy = msgspec.structs.replace(live.replica.uplink, cache_ttl=0)
    uplink_copy.uplink_id = LINK_ID
    live.replica.uplink = uplink_copy
    r = await live.client.get("/auth/api/forward", headers=_app_headers(secret))
    assert r.status_code == 503

    # Drift while the channel is down, then let the client auto-reconnect
    ops_db.update_user_display_name(test_user.uuid, "While Down")
    await live.start_server(live.port)
    await wait_for("reconnect", lambda: live.replica.available(), timeout=20)
    assert (
        live.replica.db.session_contexts[key].user.display_name == "While Down"
    )  # snapshot reconciled the drift
    r = await live.client.get("/auth/api/forward", headers=_app_headers(secret))
    assert r.status_code == 204


@pytest.mark.asyncio
async def test_unlink_stops_replica(live_remote):
    """Unlinking drops the uplink, its domains and the replica."""
    live = live_remote
    await satellite.manager.unlink(LINK_ID)
    assert LINK_ID not in satellite.manager.replicas
    assert LINK_ID not in live.db.uplinks


@pytest.mark.asyncio
async def test_live_revocation_unlinks_satellite(live_remote):
    """Revoking the link upstream drops the connection; the satellite's
    handshake retry gets a policy close and unlinks its side."""
    live = live_remote
    ops_db.delete_satellite_link(LINK_ID)
    await sync.close_link(LINK_ID)
    await wait_for(
        "satellite to unlink", lambda: LINK_ID not in live.db.uplinks, timeout=25
    )
    assert LINK_ID not in satellite.manager.replicas


@pytest.mark.asyncio
async def test_live_out_of_scope_session_not_replicated(
    live_remote, test_user, test_credential, remote_credential
):
    """The feed is scoped to the link's rp-ids: sessions of other domains
    (here the satellite's own) never cross the wire."""
    live = live_remote
    local_key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        host="localhost:4401",
        rp_id=TEST_RP_ID,
    )
    # Positive control: an in-scope session created afterwards does arrive,
    # so the out-of-scope one has already passed through the pipe.
    remote_key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for(
        "in-scope session sync", lambda: remote_key in live.replica.db.sessions
    )
    assert local_key not in live.replica.db.sessions


@pytest.mark.asyncio
async def test_live_out_of_scope_writebehind_ignored(
    live_remote, test_user, test_credential, remote_credential
):
    """A session_refresh for a session outside the link's scope is ignored
    by the upstream (fail-closed), while an in-scope one lands."""
    live = live_remote
    stale = datetime.now(UTC) - timedelta(minutes=10)
    local_key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        host="localhost:4401",
        rp_id=TEST_RP_ID,
    )
    remote_key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    ops_db.update_session(local_key, validated=stale)
    ops_db.update_session(remote_key, validated=stale)

    now = datetime.now(UTC)
    live.replica.refresh_session(local_key, now, None, None)
    live.replica.refresh_session(remote_key, now, None, None)
    await wait_for(
        "in-scope refresh to land",
        lambda: live.db.sessions[remote_key].validated > stale,
    )
    assert live.db.sessions[local_key].validated == stale


@pytest.mark.asyncio
async def test_live_scope_shrink_stops_feed(live_remote, test_user, remote_credential):
    """Narrowing the link's scope on the upstream takes effect on the live
    connection: sessions of removed domains stop flowing."""
    live = live_remote
    ops_db.set_satellite_link_scope(LINK_ID, [])
    sync.push_link_domains(LINK_ID)

    removed_key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    # Positive control: widen the scope again; a session created now does
    # arrive, so the earlier one demonstrably passed a closed pipe.
    ops_db.set_satellite_link_scope(LINK_ID, [REMOTE_DOMAIN])
    sync.push_link_domains(LINK_ID)
    remote_key, _ = create_test_session(
        user_uuid=test_user.uuid,
        credential_uuid=remote_credential.uuid,
        host=APP_HOST,
        rp_id=REMOTE_DOMAIN,
    )
    await wait_for(
        "re-scoped session sync", lambda: remote_key in live.replica.db.sessions
    )
    assert removed_key not in live.replica.db.sessions


@pytest.mark.asyncio
async def test_live_domain_conflict_reported_upstream(live_remote, test_db):
    """A pushed domain the satellite serves locally is rejected, and the
    rejection is reported into the upstream's link state."""
    # The shared config now holds the domain authoritatively — from the
    # satellite's view this is the local-conflict case.
    ops_db.create_domain(
        REMOTE_DOMAIN,
        DomainConfig(
            rp_name="Example",
            origins={
                f"**.{REMOTE_DOMAIN}": True,
                f"auth.{REMOTE_DOMAIN}": OriginEntry(auth_host=True),
            },
        ),
    )
    sync.push_link_domains(LINK_ID)
    await wait_for(
        "rejection to arrive",
        lambda: (
            REMOTE_DOMAIN in sync.links_status().get(LINK_ID, {}).get("rejected", {})
        ),
    )
    # The satellite kept its (synthetic) registry — no local overwrite
    assert test_db.config.domains[REMOTE_DOMAIN].remote is None
