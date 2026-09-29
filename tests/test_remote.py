"""Tests for remote (satellite) domains: config, replica application, feed."""

import asyncio
import secrets
import time
from datetime import UTC, datetime
from uuid import UUID

import httpx
import msgspec
import pytest
import pytest_asyncio
from fastapi import Response

import paskia.db.operations as ops_db
from paskia import domains, satellite, syncfeed
from paskia.db.structs import (
    DB,
    Config,
    Credential,
    DomainConfig,
    Org,
    OriginEntry,
    Permission,
    RemoteConfig,
    Role,
    Session,
    User,
)
from paskia.fastapi.mainapp import app
from paskia.fastapi.session import AUTH_COOKIE_NAME
from paskia.util.crypto import hash_secret

from .conftest import TEST_RP_ID

REMOTE_URL = "http://remote.test"


def _remote_domain_config(**kw) -> Config:
    return Config(
        domains={
            TEST_RP_ID: DomainConfig(origins={f"**.{TEST_RP_ID}": True}),
            "example.com": DomainConfig(
                origins={
                    "**.example.com": True,
                    "auth.example.com": OriginEntry(auth_host=True),
                },
                remote=RemoteConfig(url=REMOTE_URL, token="t", **kw),
            ),
        }
    )


def test_remote_domain_valid():
    domains.validate_config(_remote_domain_config())


def test_remote_domain_requires_auth_host():
    config = _remote_domain_config()
    config.domains["example.com"].origins = {"**.example.com": True}
    with pytest.raises(ValueError, match="auth host"):
        domains.validate_config(config)


def test_remote_domain_requires_http_url():
    config = _remote_domain_config()
    config.domains["example.com"].remote.url = "ftp://x"
    with pytest.raises(ValueError, match="http"):
        domains.validate_config(config)


def test_sanitize_preserves_remote():
    config, warnings = domains.sanitize_config(_remote_domain_config())
    assert not warnings
    assert config.domains["example.com"].remote.url == REMOTE_URL


def test_apply_upsert_and_delete():
    replica = DB()
    user = User.create(display_name="U", role=UUID(int=1))
    user.uuid = UUID(int=2)
    satellite._apply(replica, "users", str(user.uuid), _builtins(user))
    assert replica.users[user.uuid].display_name == "U"
    satellite._apply(replica, "users", str(user.uuid), None)
    assert not replica.users


def _builtins(obj):
    return msgspec.to_builtins(obj)


def test_apply_session_roundtrip():
    """Sessions keep their string key and datetime/UUID fields."""
    replica = DB()
    session = Session.create(
        user=UUID(int=1),
        credential=UUID(int=2),
        key=hash_secret("cookie", "sekret"),
        host="app2.example.com",
        ip="127.0.0.1",
        user_agent="ua",
        validated=datetime.now(UTC),
        rp_id="example.com",
    )
    satellite._apply(replica, "sessions", session.key, _builtins(session))
    stored = replica.sessions[session.key]
    assert stored.host == "app2.example.com"
    assert stored.validated == session.validated
    assert stored.user_uuid == UUID(int=1)


def test_apply_credential_bytes_roundtrip():
    """credential_id/public_key are bytes over the wire (base64 in JSON)."""
    replica = DB()
    cred = Credential.create(
        credential_id=secrets.token_bytes(32),
        user=UUID(int=1),
        aaguid=UUID(int=0),
        public_key=secrets.token_bytes(64),
        sign_count=3,
        rp_id="example.com",
    )
    cred.uuid = UUID(int=9)
    # Simulate the full wire path: builtins -> JSON -> builtins
    wire = msgspec.json.decode(msgspec.json.encode(_builtins(cred)))
    satellite._apply(replica, "credentials", str(cred.uuid), wire)
    stored = replica.credentials[cred.uuid]
    assert stored.credential_id == cred.credential_id
    assert stored.public_key == cred.public_key
    assert stored.sign_count == 3


def test_feed_emit_to_subscribers():
    queue = syncfeed.subscribe()
    try:
        user = User.create(display_name="A", role=UUID(int=1))
        syncfeed.emit("users", "k1", user)
        syncfeed.emit("users", "k1", None)
        assert queue.get_nowait()["fields"]["display_name"] == "A"
        assert queue.get_nowait()["fields"] is None
    finally:
        syncfeed.unsubscribe(queue)


def test_feed_drops_full_queue():
    queue = syncfeed.subscribe()
    try:
        for i in range(1001):
            syncfeed.emit("users", f"k{i}", None)
        assert queue.qsize() == 1000
        syncfeed.emit("users", "k1001", None)  # subscriber already dropped
        assert queue.qsize() == 1000
    finally:
        syncfeed.unsubscribe(queue)


@pytest.mark.asyncio
async def test_operations_emit_events(test_db):
    """Writes through db.operations land on the sync feed."""
    queue = syncfeed.subscribe()
    try:
        user = next(iter(test_db.users.values()))
        ops_db.update_user_display_name(user.uuid, "Renamed")
        event = queue.get_nowait()
        assert event["table"] == "users"
        assert event["key"] == str(user.uuid)
        assert event["fields"]["display_name"] == "Renamed"
    finally:
        syncfeed.unsubscribe(queue)


@pytest.mark.asyncio
async def test_replica_refresh_and_evict():
    replica = satellite.RemoteReplica(RemoteConfig(url=REMOTE_URL, token="t"))
    token = secrets.token_urlsafe(12)
    session = Session.create(
        user=UUID(int=1),
        credential=UUID(int=2),
        key=hash_secret("cookie", token),
        host="app2.example.com",
        ip="1.1.1.1",
        user_agent="ua",
        validated=datetime(2020, 1, 1, tzinfo=UTC),
    )
    replica.db.sessions[session.key] = session

    now = datetime.now(UTC)
    replica.refresh_session(session.key, now, "2.2.2.2", "new-ua")
    assert replica.db.sessions[session.key].validated == now
    queued = replica._pending_refresh[session.key]
    assert queued["type"] == "session_refresh"
    assert queued["ip"] == "2.2.2.2"

    # Host-keyed dispatch eviction (the replica's domain is resolved by host)
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(_remote_domain_config())
    satellite.manager.replicas[REMOTE_URL] = replica
    satellite.evict_session(token, "app2.example.com")
    assert not replica.db.sessions
    satellite.manager.replicas.pop(REMOTE_URL)


def test_availability_gate():
    replica = satellite.RemoteReplica(
        RemoteConfig(url=REMOTE_URL, token="t", cache_ttl=60)
    )
    assert not replica.available()  # never synced
    replica.last_contact = time.monotonic()
    assert replica.available()


# -------------------------------------------------------------------------
# API-level: endpoints served from an injected replica
# -------------------------------------------------------------------------


def _replica_db() -> tuple[DB, str]:
    """A replica DB holding one org/role/perm/user/credential/session."""
    replica = DB()
    org = Org.create(display_name="Org")
    org.uuid = UUID(int=101)
    replica.orgs[org.uuid] = org
    perm = Permission.create(scope="auth:admin", display_name="Admin")
    perm.uuid = UUID(int=102)
    perm.orgs[org.uuid] = True
    replica.permissions[perm.uuid] = perm
    role = Role.create(org=org.uuid, display_name="Admins", permissions={perm.uuid})
    role.uuid = UUID(int=103)
    replica.roles[role.uuid] = role
    user = User.create(display_name="Remote Admin", role=role.uuid)
    user.uuid = UUID(int=104)
    replica.users[user.uuid] = user
    cred = Credential.create(
        credential_id=b"cid",
        user=user.uuid,
        aaguid=UUID(int=0),
        public_key=b"pk",
        sign_count=0,
        rp_id="example.com",
    )
    cred.uuid = UUID(int=105)
    replica.credentials[cred.uuid] = cred
    secret = secrets.token_urlsafe(12)
    session = Session.create(
        user=user.uuid,
        credential=cred.uuid,
        key=hash_secret("cookie", secret),
        host="app2.example.com",
        ip="127.0.0.1",
        user_agent="pytest",
        validated=datetime.now(UTC),
        rp_id="example.com",
    )
    replica.sessions[session.key] = session
    return replica, secret


@pytest_asyncio.fixture
async def remote_client(test_db):
    """ASGI client with example.com as a remote domain on a warm replica."""
    config = _remote_domain_config()
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(config)
    replica_db, secret = _replica_db()
    replica = satellite.RemoteReplica(RemoteConfig(url=REMOTE_URL, token="t"))
    replica.db = replica_db
    replica.last_contact = time.monotonic()
    replica.connected = True
    satellite.manager.replicas[REMOTE_URL] = replica
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:4401"
    ) as client:
        yield client, secret, replica
    satellite.manager.replicas.pop(REMOTE_URL, None)


@pytest.mark.asyncio
async def test_forward_served_from_replica(remote_client):
    client, secret, _ = remote_client
    r = await client.get(
        "/auth/api/forward?perm=auth:admin",
        headers={"Host": "app2.example.com", "Cookie": f"{AUTH_COOKIE_NAME}={secret}"},
    )
    assert r.status_code == 204
    assert r.headers["remote-name"] == "Remote Admin"
    assert r.headers["remote-groups"] == "auth:admin"


@pytest.mark.asyncio
async def test_forward_replica_denies_missing_perm(remote_client):
    client, secret, _ = remote_client
    r = await client.get(
        "/auth/api/forward?perm=other:scope",
        headers={"Host": "app2.example.com", "Cookie": f"{AUTH_COOKIE_NAME}={secret}"},
    )
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_validate_renews_locally_and_queues_writebehind(remote_client):
    client, secret, replica = remote_client
    session = next(iter(replica.db.sessions.values()))
    session.validated = datetime(2020, 1, 1, tzinfo=UTC)  # force refresh threshold
    r = await client.post(
        "/auth/api/validate",
        headers={"Host": "app2.example.com", "Cookie": f"{AUTH_COOKIE_NAME}={secret}"},
    )
    assert r.status_code == 200
    assert r.json()["renewed"] is True
    assert session.validated.year > 2020  # applied to the replica
    queued = replica._pending_refresh[session.key]
    assert queued["type"] == "session_refresh"


@pytest.mark.asyncio
async def test_remote_domain_503_when_replica_stale(remote_client):
    client, secret, replica = remote_client
    replica.connected = False
    replica.last_contact = 0
    r = await client.get(
        "/auth/api/forward",
        headers={"Host": "app2.example.com", "Cookie": f"{AUTH_COOKIE_NAME}={secret}"},
    )
    assert r.status_code == 503


@pytest.mark.asyncio
async def test_logout_proxied_and_evicted(remote_client, monkeypatch):
    client, secret, replica = remote_client

    async def fake_forward(request):
        return Response(status_code=200, content=b'{"message": "Logged out"}')

    monkeypatch.setattr(satellite, "forward_request", fake_forward)
    r = await client.post(
        "/auth/api/logout",
        headers={"Host": "app2.example.com", "Cookie": f"{AUTH_COOKIE_NAME}={secret}"},
    )
    assert r.status_code == 200
    assert not replica.db.sessions  # evicted optimistically


@pytest.mark.asyncio
async def test_admin_configures_remote_domain(client, session_token, test_db):
    """The admin domains API stores remote config and masks the token."""
    r = await client.post(
        "/auth/api/admin/domains/",
        json={
            "rp_id": "example.com",
            "rp_name": "Example",
            "origins": {
                "**.example.com": True,
                "auth.example.com": {"auth_host": True},
            },
            "remote": {"url": "http://remote.test", "token": "sekret", "cache_ttl": 30},
        },
        headers={
            "Host": "localhost:4401",
            "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
        },
    )
    assert r.status_code == 200, r.text
    stored = test_db.config.domains["example.com"]
    assert stored.remote.url == "http://remote.test"
    assert stored.remote.token == "sekret"

    r = await client.get(
        "/auth/api/admin/domains/",
        headers={
            "Host": "localhost:4401",
            "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
        },
    )
    entry = next(d for d in r.json() if d["rp_id"] == "example.com")
    assert entry["remote"]["url"] == "http://remote.test"
    assert "token" not in entry["remote"]  # write-only

    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }
    origins = {"**.example.com": True, "auth.example.com": {"auth_host": True}}

    # PATCH without the remote key preserves it (and its token)
    r = await client.patch(
        "/auth/api/admin/domains/example.com",
        json={"rp_name": "Ex", "origins": origins},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert stored.remote.url == "http://remote.test"
    assert stored.remote.token == "sekret"

    # PATCH with a new URL but no token keeps the stored token
    r = await client.patch(
        "/auth/api/admin/domains/example.com",
        json={
            "rp_name": "Ex",
            "origins": origins,
            "remote": {"url": "http://other.test", "cache_ttl": 30},
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert stored.remote.url == "http://other.test"
    assert stored.remote.token == "sekret"

    # PATCH with remote: null clears it
    r = await client.patch(
        "/auth/api/admin/domains/example.com",
        json={"rp_name": "Ex", "origins": origins, "remote": None},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    assert stored.remote is None


@pytest.mark.asyncio
async def test_admin_remote_domain_requires_auth_host(client, session_token):
    r = await client.post(
        "/auth/api/admin/domains/",
        json={
            "rp_id": "example.com",
            "origins": {"**.example.com": True},
            "remote": {"url": "http://remote.test"},
        },
        headers={
            "Host": "localhost:4401",
            "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
        },
    )
    assert r.status_code == 400
    assert "auth host" in r.json()["detail"]


@pytest.mark.asyncio
async def test_admin_remote_values_clamped(client, session_token, test_db):
    """Nonsensical TTL/interval values are clamped to the supported floor."""
    r = await client.post(
        "/auth/api/admin/domains/",
        json={
            "rp_id": "example.com",
            "origins": {
                "**.example.com": True,
                "auth.example.com": {"auth_host": True},
            },
            "remote": {
                "url": "http://remote.test",
                "token": "t",
                "cache_ttl": -5,
                "refresh_interval": 1,
            },
        },
        headers={
            "Host": "localhost:4401",
            "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
        },
    )
    assert r.status_code == 200, r.text
    remote = test_db.config.domains["example.com"].remote
    assert remote.cache_ttl == 1
    assert remote.refresh_interval == 30


def _add_shared_remote(config: Config, token: str) -> None:
    config.domains["sub.example.com"] = DomainConfig(
        origins={
            "**.sub.example.com": True,
            "auth.sub.example.com": OriginEntry(auth_host=True),
        },
        remote=RemoteConfig(url=REMOTE_URL, token=token),
    )


def test_shared_remote_same_settings_ok():
    config = _remote_domain_config()
    _add_shared_remote(config, token="t")
    domains.validate_config(config)


def test_shared_remote_conflicting_settings_rejected():
    config = _remote_domain_config()
    _add_shared_remote(config, token="different")
    with pytest.raises(ValueError, match="conflicting"):
        domains.validate_config(config)


def test_sanitize_aligns_conflicting_shared_remote():
    config = _remote_domain_config()
    _add_shared_remote(config, token="different")
    sanitized, warnings = domains.sanitize_config(config)
    assert any("conflict" in w for w in warnings)
    # Aligned to the first configuration, and the result validates
    assert sanitized.domains["sub.example.com"].remote.token == "t"
    domains.validate_config(sanitized)


def test_rebuild_listener_skipped_without_running_loop():
    """A registry rebuild outside an event loop warns instead of crashing."""

    async def listener(_registry):
        raise AssertionError("must not run")  # pragma: no cover

    domains.add_rebuild_listener(listener)
    try:
        domains.init_registry(_remote_domain_config())
    finally:
        domains.remove_rebuild_listener(listener)


@pytest.mark.asyncio
async def test_rebuild_listener_runs_with_loop():
    ran = asyncio.Event()

    async def listener(_registry):
        ran.set()

    domains.add_rebuild_listener(listener)
    try:
        domains.init_registry(_remote_domain_config())
        await asyncio.wait_for(ran.wait(), 2)
    finally:
        domains.remove_rebuild_listener(listener)


@pytest.mark.asyncio
async def test_settings_reports_remote_flag(remote_client):
    client, _, _ = remote_client
    r = await client.get("/auth/api/settings", headers={"Host": "app2.example.com"})
    assert r.status_code == 200
    assert r.json()["remote"] is True
    r = await client.get("/auth/api/settings", headers={"Host": "localhost:4401"})
    assert r.json()["remote"] is False


@pytest.mark.asyncio
async def test_logout_remote_down_returns_503(remote_client, monkeypatch):
    """A transport failure on a proxied call is a deliberate 503, not a 500."""
    client, secret, replica = remote_client

    class Down:
        async def request(self, *args, **kwargs):
            raise httpx.ConnectError("down")

    monkeypatch.setitem(satellite._clients, REMOTE_URL, Down())
    r = await client.post(
        "/auth/api/logout",
        headers={"Host": "app2.example.com", "Cookie": f"{AUTH_COOKIE_NAME}={secret}"},
    )
    assert r.status_code == 503
    # Not evicted: the remote never saw the logout, the session is still valid
    assert replica.db.sessions


@pytest.mark.asyncio
async def test_user_api_proxied_on_remote_auth_host(remote_client, monkeypatch):
    """Profile traffic for a remote domain's auth host is forwarded, never
    written to the satellite's local database."""
    client, _, _ = remote_client

    async def fake_forward(request):
        return Response(status_code=200, content=b"proxied")

    monkeypatch.setattr(satellite, "forward_request", fake_forward)
    r = await client.get(
        f"/auth/api/user/{UUID(int=104)}/profile.webp",
        headers={"Host": "auth.example.com"},
    )
    assert r.status_code == 200
    assert r.content == b"proxied"
