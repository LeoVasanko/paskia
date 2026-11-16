"""Tests for remote (satellite) domains: config, links, replica, feed."""

import secrets
import time
from datetime import UTC, datetime
from uuid import UUID

import httpx
import msgspec
import pytest
import pytest_asyncio
from fastapi import Request, Response

import paskia.db.operations as ops_db
from paskia import domains, satellite, syncfeed
from paskia.db.structs import (
    Config,
    Credential,
    DomainConfig,
    OriginEntry,
    RemoteConfig,
    Session,
    Uplink,
    User,
)
from paskia.fastapi import sync
from paskia.fastapi.mainapp import app
from paskia.fastapi.session import AUTH_COOKIE_NAME
from paskia.util.apistructs import (
    ApiOrgContext,
    ApiRoleContext,
    ApiSessionContext,
    ApiUserContext,
)
from paskia.util.crypto import hash_secret

from .conftest import TEST_RP_ID, create_test_session

REMOTE_URL = "http://remote.test"
UPLINK_ID = "up1"


def _api_ctx(display_name="Remote Admin", permissions=("auth:admin",)):
    """An upstream-pushed per-session context, as embedded in session events."""
    return ApiSessionContext(
        user=ApiUserContext(uuid=UUID(int=104), display_name=display_name),
        org=ApiOrgContext(uuid=UUID(int=101), display_name="Org"),
        role=ApiRoleContext(uuid=UUID(int=103), display_name="Admins"),
        permissions=list(permissions),
    )


def _uplink(**kw) -> Uplink:
    uplink = Uplink(url=REMOTE_URL, created=datetime.now(UTC), key=b"k", **kw)
    uplink.uplink_id = UPLINK_ID
    return uplink


def _remote_domain_config(**kw) -> Config:
    return Config(
        domains={
            TEST_RP_ID: DomainConfig(origins={f"**.{TEST_RP_ID}": True}),
            "example.com": DomainConfig(
                origins={
                    "**.example.com": True,
                    "auth.example.com": OriginEntry(auth_host=True),
                },
                remote=RemoteConfig(link=UPLINK_ID, **kw),
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


def test_sanitize_preserves_remote():
    config, warnings = domains.sanitize_config(_remote_domain_config())
    assert not warnings
    assert config.domains["example.com"].remote.link == UPLINK_ID


def test_sanitize_drops_remote_without_link():
    """A remote config pointing nowhere (e.g. a v1 leftover) degrades to a
    plain local domain instead of failing to serve."""
    config = _remote_domain_config()
    config.domains["example.com"].remote = RemoteConfig()
    sanitized, warnings = domains.sanitize_config(config)
    assert any("remote dropped" in w for w in warnings)
    assert sanitized.domains["example.com"].remote is None
    domains.validate_config(sanitized)


def test_apply_upsert_and_delete():
    replica = satellite.ReplicaDB()
    cred = Credential.create(
        credential_id=b"cid",
        user=UUID(int=1),
        aaguid=UUID(int=0),
        public_key=b"pk",
        sign_count=0,
        rp_id="example.com",
    )
    cred.uuid = UUID(int=2)
    satellite._apply(replica, "credentials", str(cred.uuid), _builtins(cred))
    assert replica.credentials[cred.uuid].public_key == b"pk"
    satellite._apply(replica, "credentials", str(cred.uuid), None)
    assert not replica.credentials


def _builtins(obj):
    return msgspec.to_builtins(obj)


def test_apply_session_roundtrip():
    """Sessions keep their string key and datetime/UUID fields; the
    embedded ctx lands in the replica's context map (and goes with it)."""
    replica = satellite.ReplicaDB()
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
    fields = _builtins(session)
    fields["ctx"] = _builtins(_api_ctx())
    satellite._apply(replica, "sessions", session.key, fields)
    stored = replica.sessions[session.key]
    assert stored.host == "app2.example.com"
    assert stored.validated == session.validated
    assert stored.user_uuid == UUID(int=1)
    assert replica.session_contexts[session.key].user.display_name == "Remote Admin"
    satellite._apply(replica, "sessions", session.key, None)
    assert not replica.sessions
    assert not replica.session_contexts


def test_apply_credential_bytes_roundtrip():
    """credential_id/public_key are bytes over the wire (base64 in JSON)."""
    replica = satellite.ReplicaDB()
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
        cred = Credential.create(
            credential_id=b"c",
            user=UUID(int=1),
            aaguid=UUID(int=0),
            public_key=b"p",
            sign_count=0,
            rp_id="example.com",
        )
        syncfeed.emit("credentials", "k1", cred)
        syncfeed.emit("credentials", "k1", None)
        assert queue.get_nowait()["fields"]["sign_count"] == 0
        assert queue.get_nowait()["fields"] is None
    finally:
        syncfeed.unsubscribe(queue)


def test_feed_drops_full_queue():
    queue = syncfeed.subscribe()
    try:
        for i in range(1001):
            syncfeed.emit("credentials", f"k{i}", None)
        assert queue.qsize() == 1000
        syncfeed.emit("credentials", "k1001", None)  # subscriber already dropped
        assert queue.qsize() == 1000
    finally:
        syncfeed.unsubscribe(queue)


@pytest.mark.asyncio
async def test_operations_repush_session_contexts(test_db, test_user, test_credential):
    """User-graph changes are never published; instead the affected
    sessions are re-pushed with a freshly computed ctx."""
    queue = syncfeed.subscribe()
    try:
        key, _ = create_test_session(
            user_uuid=test_user.uuid, credential_uuid=test_credential.uuid
        )
        _drain(queue)  # the session store itself emits (with ctx)
        ops_db.update_user_display_name(test_user.uuid, "Renamed")
        events = _drain(queue)
        assert all(e["table"] != "users" for e in events)
        repushed = [e for e in events if e["table"] == "sessions" and e["key"] == key]
        assert repushed
        assert repushed[-1]["fields"]["ctx"]["user"]["display_name"] == "Renamed"
    finally:
        syncfeed.unsubscribe(queue)


@pytest.mark.asyncio
async def test_replica_refresh_and_evict():
    replica = satellite.UplinkReplica(_uplink())
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

    # Host-keyed dispatch eviction (the replica's uplink is resolved by host)
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(_remote_domain_config())
    satellite.manager.replicas[UPLINK_ID] = replica
    satellite.evict_session(token, "app2.example.com")
    assert not replica.db.sessions
    satellite.manager.replicas.pop(UPLINK_ID)


def test_availability_gate():
    replica = satellite.UplinkReplica(_uplink(cache_ttl=60))
    assert not replica.available()  # never synced
    replica.last_contact = time.monotonic()
    assert replica.available()


# -------------------------------------------------------------------------
# Link URLs and registration offers
# -------------------------------------------------------------------------


def _offer_id(secret: bytes) -> str:
    return next(key for key, offer in sync._offers.items() if offer.secret == secret)


def test_parse_link_url():
    url = sync.create_offer([], "https://auth.example.com")
    base, secret = satellite.parse_link_url(url)
    assert base == "https://auth.example.com"
    assert url.startswith("wss://auth.example.com#")
    assert sync._offers[_offer_id(secret)].secret == secret

    url = sync.create_offer([], "http://127.0.0.1:4401")
    base, secret = satellite.parse_link_url(url)
    assert base == "http://127.0.0.1:4401"
    assert len(secret) == 32
    with pytest.raises(ValueError, match="wss"):
        satellite.parse_link_url("https://alpha.bravo@auth.example.com")
    with pytest.raises(ValueError, match="key"):
        satellite.parse_link_url("wss://auth.example.com")


def test_offer_mint_and_spend(test_db):
    """Offers are RAM-only and spent by the credential's atomic key change."""
    url = sync.create_offer(["example.com"], "https://auth.example.com")
    _base, secret = satellite.parse_link_url(url)
    offer_id = _offer_id(secret)
    offer = sync._offers[offer_id]
    assert offer.rp_ids == ["example.com"]
    store = sync._HandshakeStore()
    store[offer_id] = b"composite credential"
    assert offer_id not in sync._offers
    assert store.registered_offer is offer

    burned_url = sync.create_offer([], "https://auth.example.com")
    _base, burned_secret = satellite.parse_link_url(burned_url)
    burned_id = _offer_id(burned_secret)
    burned_store = sync._HandshakeStore()
    del burned_store[burned_id]
    assert burned_id not in sync._offers

    expired = sync.create_offer([], "http://127.0.0.1:4401")
    assert expired.startswith("ws://")
    _base, expired_secret = satellite.parse_link_url(expired)
    expired_id = _offer_id(expired_secret)
    sync._offers[expired_id].created -= sync.OFFER_TTL + 1
    sync._sweep_offers()
    assert expired_id not in sync._offers


# -------------------------------------------------------------------------
# Pushed-domain application (satellite side)
# -------------------------------------------------------------------------

_PUSHED = {
    "rp_id": "example.com",
    "rp_name": "Example",
    "origins": {"**.example.com": True, "auth.example.com": {"auth_host": True}},
}


@pytest.mark.asyncio
async def test_apply_domains_push_accept_and_remove(test_db, domain_registry):
    """A push persists the accepted set (marked remote via the link); a
    later push without the domain removes it."""
    rejected, changed = satellite.apply_domains_push(UPLINK_ID, [_PUSHED])
    assert not rejected
    assert changed
    domain = test_db.config.domains["example.com"]
    assert domain.remote.link == UPLINK_ID
    assert domain.rp_name == "Example"
    assert domains.registry().get("example.com").remote is not None

    # Idempotent: the same push again changes nothing
    rejected, changed = satellite.apply_domains_push(UPLINK_ID, [_PUSHED])
    assert not rejected and not changed

    # The uplink's scope shrank: the domain leaves the local config
    rejected, changed = satellite.apply_domains_push(UPLINK_ID, [])
    assert not rejected
    assert changed
    assert "example.com" not in test_db.config.domains
    assert domains.registry().get("example.com") is None


@pytest.mark.asyncio
async def test_apply_domains_push_rejects_local_conflict(test_db, domain_registry):
    """A pushed rp-id that this instance serves locally is rejected."""
    rejected, changed = satellite.apply_domains_push(
        UPLINK_ID, [{**_PUSHED, "rp_id": TEST_RP_ID}]
    )
    assert TEST_RP_ID in rejected
    assert not changed
    assert test_db.config.domains[TEST_RP_ID].remote is None


@pytest.mark.asyncio
async def test_apply_domains_push_rejects_auth_host_collision(test_db, domain_registry):
    """A pushed auth host that collides with a local rp-id is rejected
    (the merged config must stay servable)."""
    rejected, _ = satellite.apply_domains_push(
        UPLINK_ID,
        [
            {
                "rp_id": "example.com",
                "rp_name": "Example",
                "origins": {"**.example.com": True, TEST_RP_ID: {"auth_host": True}},
            }
        ],
    )
    assert "example.com" in rejected
    assert "example.com" not in test_db.config.domains


# -------------------------------------------------------------------------
# API-level: endpoints served from an injected replica
# -------------------------------------------------------------------------


def _replica_db() -> tuple[satellite.ReplicaDB, str]:
    """A replica holding one credential/session and its pushed context."""
    replica = satellite.ReplicaDB()
    cred = Credential.create(
        credential_id=b"cid",
        user=UUID(int=104),
        aaguid=UUID(int=0),
        public_key=b"pk",
        sign_count=0,
        rp_id="example.com",
    )
    cred.uuid = UUID(int=105)
    replica.credentials[cred.uuid] = cred
    secret = secrets.token_urlsafe(12)
    session = Session.create(
        user=UUID(int=104),
        credential=cred.uuid,
        key=hash_secret("cookie", secret),
        host="app2.example.com",
        ip="127.0.0.1",
        user_agent="pytest",
        validated=datetime.now(UTC),
        rp_id="example.com",
    )
    replica.sessions[session.key] = session
    replica.session_contexts[session.key] = _api_ctx()
    return replica, secret


@pytest_asyncio.fixture
async def remote_client(test_db):
    """ASGI client with example.com as a remote domain on a warm replica."""
    config = _remote_domain_config()
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(config)
    ops_db.create_uplink(UPLINK_ID, _uplink(), {})
    replica_db, secret = _replica_db()
    replica = satellite.UplinkReplica(_uplink())
    replica.db = replica_db
    replica.last_contact = time.monotonic()
    replica.connected = True
    satellite.manager.replicas[UPLINK_ID] = replica
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:4401"
    ) as client:
        yield client, secret, replica
    satellite.manager.replicas.pop(UPLINK_ID, None)


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
    assert not replica.db.session_contexts


@pytest.mark.asyncio
async def test_admin_rejects_remote_writes(client, session_token, test_db):
    """Remote domains are uplink-managed: the domains API refuses to
    create, edit or delete them."""
    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }
    r = await client.post(
        "/auth/api/admin/domains/",
        json={
            "rp_id": "example.com",
            "origins": {
                "**.example.com": True,
                "auth.example.com": {"auth_host": True},
            },
            "remote": {"link": "x"},
        },
        headers=headers,
    )
    assert r.status_code == 400
    assert "uplink" in r.json()["detail"]

    # An existing remote domain (as an uplink push would have stored it)
    ops_db.apply_uplink_domains(
        UPLINK_ID,
        {
            "example.com": DomainConfig(
                rp_name="Example",
                origins={
                    "**.example.com": True,
                    "auth.example.com": OriginEntry(auth_host=True),
                },
                remote=RemoteConfig(link=UPLINK_ID),
            )
        },
    )
    r = await client.patch(
        "/auth/api/admin/domains/example.com",
        json={"rp_name": "Ex", "origins": {"**.example.com": True}},
        headers=headers,
    )
    assert r.status_code == 400
    assert "uplink" in r.json()["detail"]
    r = await client.delete("/auth/api/admin/domains/example.com", headers=headers)
    assert r.status_code == 400
    assert "unlink" in r.json()["detail"]


def test_feed_scoped_subscription_filters():
    """A scoped subscriber gets only its rp-ids' sessions/credentials
    (upserts filtered, deletes passed); the user graph is never published."""
    scoped = syncfeed.subscribe({"example.com"})
    try:
        in_scope = Session.create(
            user=UUID(int=1),
            credential=UUID(int=2),
            key="k1",
            host="app2.example.com",
            ip="1.1.1.1",
            user_agent="ua",
            validated=datetime.now(UTC),
            rp_id="example.com",
        )
        out_scope = Session.create(
            user=UUID(int=1),
            credential=UUID(int=3),
            key="k2",
            host="localhost",
            ip="1.1.1.1",
            user_agent="ua",
            validated=datetime.now(UTC),
            rp_id="localhost",
        )
        syncfeed.emit("sessions", "k1", in_scope)
        syncfeed.emit("sessions", "k2", out_scope)
        syncfeed.emit("users", "u1", User.create(display_name="A", role=UUID(int=1)))
        syncfeed.emit("sessions", "k2", None)  # deletes pass regardless
        assert [e["key"] for e in _drain(scoped)] == ["k1", "k2"]
    finally:
        syncfeed.unsubscribe(scoped)


def test_feed_scope_updates_live():
    """The subscriber scope is mutable in place: a link's scope adjustment
    takes effect without a reconnect."""
    scope = {"example.com"}
    queue = syncfeed.subscribe(scope)
    try:
        session = Session.create(
            user=UUID(int=1),
            credential=UUID(int=2),
            key="k1",
            host="localhost",
            ip="1.1.1.1",
            user_agent="ua",
            validated=datetime.now(UTC),
            rp_id="localhost",
        )
        syncfeed.emit("sessions", "k1", session)
        assert not _drain(queue)
        scope.add("localhost")  # scope widened live
        syncfeed.emit("sessions", "k1", session)
        assert [e["key"] for e in _drain(queue)] == ["k1"]
    finally:
        syncfeed.unsubscribe(queue)


def _drain(queue):
    items = []
    while not queue.empty():
        items.append(queue.get_nowait())
    return items


@pytest.mark.asyncio
async def test_settings_reports_remote_flag(remote_client):
    client, _, _ = remote_client
    r = await client.get("/auth/api/settings", headers={"Host": "app2.example.com"})
    assert r.status_code == 200
    assert r.json()["remote"] is True
    r = await client.get("/auth/api/settings", headers={"Host": "localhost:4401"})
    assert r.json()["remote"] is False


@pytest.mark.asyncio
async def test_logout_remote_down_returns_503(remote_client):
    """A transport failure on a proxied call is a deliberate 503, not a 500."""
    client, secret, replica = remote_client
    replica.connected = False
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


@pytest.mark.asyncio
async def test_satellite_asgi_request_and_response():
    replica = satellite.UplinkReplica(_uplink())
    sent = {}

    class Socket:
        async def send(self, data):
            sent.update(msgspec.json.decode(data))
            for message in [
                {
                    "type": "http.response.start",
                    "id": sent["id"],
                    "status": 201,
                    "headers": [(b"set-cookie", b"a=1"), (b"set-cookie", b"b=2")],
                },
                {
                    "type": "http.response.body",
                    "id": sent["id"],
                    "body": b"first",
                    "more_body": True,
                },
                {"type": "http.response.body", "id": sent["id"], "body": b"second"},
            ]:
                replica._receive_asgi(msgspec.json.decode(syncfeed.encode(message)))

    replica._sock = Socket()
    replica.connected = True

    async def receive():
        return {"type": "http.request", "body": b"payload", "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": "/auth/api/set-session",
            "raw_path": b"/auth/api/set-session",
            "query_string": b"a=1",
            "headers": [(b"host", b"app2.example.com")],
            "client": ("127.0.0.1", 1234),
        },
        receive,
    )
    response = await replica.forward(request)

    assert sent["type"] == "http.request"
    assert syncfeed.decode_bytes(sent["body"]) == b"payload"
    assert sent["scope"]["path"] == "/auth/api/set-session"
    assert syncfeed.decode_bytes(sent["scope"]["query_string"]) == b"a=1"
    assert [
        tuple(syncfeed.decode_bytes(value) for value in pair)
        for pair in sent["scope"]["headers"]
    ] == [(b"host", b"app2.example.com")]
    assert response.status_code == 201
    assert response.body == b"firstsecond"
    assert response.headers.getlist("set-cookie") == ["a=1", "b=2"]


@pytest.mark.asyncio
async def test_upstream_asgi_scope_and_response_frames(test_db, monkeypatch):
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(_remote_domain_config())
    seen = {}

    async def application(scope, receive, send):
        seen["scope"] = scope
        seen["request"] = await receive()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"set-cookie", b"a=1"), (b"set-cookie", b"b=2")],
            }
        )
        await send({"type": "http.response.body", "body": b"first", "more_body": True})
        await send({"type": "http.response.body", "body": b"second"})

    class Socket:
        def __init__(self):
            self.messages = []

        async def send(self, data):
            self.messages.append(msgspec.json.decode(data))

    monkeypatch.setattr(sync, "_asgi_app", application)
    sock = Socket()
    conn = sync._Connection(ws=sock, link_id=UPLINK_ID, scope={"example.com"})
    await sync._run_asgi(
        {
            "id": "call-1",
            "scope": {
                "method": "POST",
                "scheme": "https",
                "path": "/auth/api/logout",
                "raw_path": b"/auth/api/logout",
                "query_string": b"a=1",
                "headers": [(b"host", b"app2.example.com")],
                "client": ["127.0.0.1", 1234],
            },
            "body": b"payload",
        },
        conn,
    )

    scope = seen["scope"]
    assert scope["paskia.forwarded"] is True
    assert scope["method"] == "POST"
    assert scope["query_string"] == b"a=1"
    assert (b"host", b"app2.example.com") in scope["headers"]
    assert seen["request"]["body"] == b"payload"
    assert [m["type"] for m in sock.messages] == [
        "http.response.start",
        "http.response.body",
        "http.response.body",
    ]
    assert all(m["id"] == "call-1" for m in sock.messages)
    assert [
        tuple(syncfeed.decode_bytes(value) for value in pair)
        for pair in sock.messages[0]["headers"]
    ] == [(b"set-cookie", b"a=1"), (b"set-cookie", b"b=2")]
    assert syncfeed.decode_bytes(
        sock.messages[1]["body"]
    ) + syncfeed.decode_bytes(sock.messages[2]["body"]) == b"firstsecond"


@pytest.mark.asyncio
async def test_upstream_asgi_whitelist(test_db, monkeypatch):
    domains.configure(listen=["localhost:4401"])
    domains.init_registry(_remote_domain_config())
    called = False

    async def application(scope, receive, send):
        nonlocal called
        called = True

    class Socket:
        def __init__(self):
            self.messages = []

        async def send(self, data):
            self.messages.append(msgspec.json.decode(data))

    monkeypatch.setattr(sync, "_asgi_app", application)
    for host, path, expected in [
        ("app2.example.com", "/auth/api/admin/domains/", 403),
        ("localhost:4401", "/auth/api/check", 421),
        ("unknown.example.org", "/auth/api/check", 421),
    ]:
        sock = Socket()
        conn = sync._Connection(ws=sock, link_id=UPLINK_ID, scope={"example.com"})
        await sync._run_asgi(
            {
                "id": "rejected",
                "scope": {
                    "path": path,
                    "headers": [(b"host", host.encode())],
                },
            },
            conn,
        )
        assert sock.messages[0]["status"] == expected
    assert called is False


# -------------------------------------------------------------------------
# Satellite links and uplinks (admin API)
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_satellite_link_lifecycle(client, session_token, test_db):
    """Offer minting (auth host required), scope adjustment, revocation."""
    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }
    r = await client.post(
        "/auth/api/admin/domains/",
        json={
            "rp_id": "example.com",
            "rp_name": "Example",
            "origins": {"**.example.com": True},
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text

    # No auth host yet — the domain cannot be scoped into a link
    r = await client.post(
        "/auth/api/admin/satellites/", json={"rp_ids": ["example.com"]}, headers=headers
    )
    assert r.status_code == 400
    assert "auth host" in r.json()["detail"]

    r = await client.patch(
        "/auth/api/admin/domains/example.com",
        json={
            "rp_name": "Example",
            "origins": {
                "**.example.com": True,
                "auth.example.com": {"auth_host": True},
            },
        },
        headers=headers,
    )
    assert r.status_code == 200, r.text

    # Mint an offer: a wss URL carrying the registration secret in its fragment
    r = await client.post(
        "/auth/api/admin/satellites/", json={"rp_ids": ["example.com"]}, headers=headers
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["url"].startswith("wss://auth.example.com#")
    _base, secret = satellite.parse_link_url(body["url"])
    assert sync._offers[_offer_id(secret)].secret == secret
    assert body["expires_in"] > 0

    # Unknown domains and nested scopes are refused
    r = await client.post(
        "/auth/api/admin/satellites/",
        json={"rp_ids": ["nope.example"]},
        headers=headers,
    )
    assert r.status_code == 400

    # Register a link directly (the handshake itself is covered live),
    # then list, adjust scope, revoke
    ops_db.create_satellite_link("ln1", ["example.com"], b"key", label="sat-1")
    r = await client.get("/auth/api/admin/satellites/", headers=headers)
    assert r.status_code == 200
    (entry,) = r.json()
    assert entry["id"] == "ln1"
    assert entry["label"] == "sat-1"
    assert entry["rp_ids"] == ["example.com"]
    assert entry["connected"] is False

    r = await client.patch(
        "/auth/api/admin/satellites/ln1", json={"rp_ids": []}, headers=headers
    )
    assert r.status_code == 200
    assert test_db.satellite_links["ln1"].rp_ids == []

    r = await client.delete("/auth/api/admin/satellites/ln1", headers=headers)
    assert r.status_code == 200
    assert not test_db.satellite_links
    r = await client.delete("/auth/api/admin/satellites/ln1", headers=headers)
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_admin_offer_scope_rejects_remote_domain(client, session_token, test_db):
    """A satellite-served domain cannot be scoped into a link: no nesting."""
    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }
    ops_db.apply_uplink_domains(
        UPLINK_ID,
        {
            "example.com": DomainConfig(
                origins={
                    "**.example.com": True,
                    "auth.example.com": OriginEntry(auth_host=True),
                },
                remote=RemoteConfig(link=UPLINK_ID),
            )
        },
    )
    r = await client.post(
        "/auth/api/admin/satellites/", json={"rp_ids": ["example.com"]}, headers=headers
    )
    assert r.status_code == 400
    assert "nested" in r.json()["detail"]


@pytest.mark.asyncio
async def test_admin_uplinks_list_and_unlink(client, session_token, test_db):
    """Uplinks list shows served domains and replica state; unlink removes
    the uplink and its domains."""
    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }
    ops_db.create_uplink(UPLINK_ID, _uplink(), {})
    ops_db.apply_uplink_domains(
        UPLINK_ID,
        {
            "example.com": DomainConfig(
                origins={
                    "**.example.com": True,
                    "auth.example.com": OriginEntry(auth_host=True),
                },
                remote=RemoteConfig(link=UPLINK_ID),
            )
        },
    )
    r = await client.get("/auth/api/admin/uplinks/", headers=headers)
    assert r.status_code == 200
    (entry,) = r.json()
    assert entry["id"] == UPLINK_ID
    assert entry["url"] == REMOTE_URL
    assert entry["domains"] == ["example.com"]
    assert entry["connected"] is False

    r = await client.delete(f"/auth/api/admin/uplinks/{UPLINK_ID}", headers=headers)
    assert r.status_code == 200
    assert not test_db.uplinks
    assert "example.com" not in test_db.config.domains
    r = await client.get("/auth/api/admin/uplinks/", headers=headers)
    assert r.json() == []


@pytest.mark.asyncio
async def test_admin_register_uplink_endpoint(client, session_token, monkeypatch):
    """The registration endpoint runs the handshake synchronously (the
    handshake itself is covered by the live tests) and reports failures."""
    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }

    async def fake_register(url):
        return {
            "link": "ln1",
            "url": "https://remote.test",
            "domains": ["example.com"],
            "rejected": {},
        }

    monkeypatch.setattr(satellite, "register_uplink", fake_register)
    r = await client.post(
        "/auth/api/admin/uplinks/",
        json={"url": "wss://remote.test#hurt.siege.right.burden.permit"},
        headers=headers,
    )
    assert r.status_code == 200
    assert r.json()["domains"] == ["example.com"]

    async def failing_register(url):
        raise RuntimeError("the upstream rejected the link URL")

    monkeypatch.setattr(satellite, "register_uplink", failing_register)
    r = await client.post(
        "/auth/api/admin/uplinks/",
        json={"url": "wss://remote.test#hurt.siege.right.burden.permit"},
        headers=headers,
    )
    assert r.status_code == 400
    assert "rejected" in r.json()["detail"]

    r = await client.post(
        "/auth/api/admin/uplinks/", json={"url": "nope"}, headers=headers
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_admin_register_uplink_rejects_self(
    client, session_token, test_db, monkeypatch
):
    headers = {
        "Host": "localhost:4401",
        "Cookie": f"{AUTH_COOKIE_NAME}={session_token}",
    }
    calls = []

    async def fake_register(url):
        calls.append(url)
        return {"link": "ln1", "url": url, "domains": [], "rejected": {}}

    monkeypatch.setattr(satellite, "register_uplink", fake_register)
    ops_db.create_domain(
        "example.com",
        DomainConfig(
            origins={
                "**.example.com": True,
                "auth.example.com": OriginEntry(auth_host=True),
            }
        ),
    )
    domains.init_registry(test_db.config)
    for url in [
        "ws://localhost:4401#hurt.siege.right.burden.permit",
        "wss://auth.example.com#hurt.siege.right.burden.permit",
    ]:
        r = await client.post(
            "/auth/api/admin/uplinks/", json={"url": url}, headers=headers
        )
        assert r.status_code == 400
        assert "different master instance" in r.json()["detail"]
    assert calls == []

    r = await client.post(
        "/auth/api/admin/uplinks/",
        json={"url": "ws://localhost:4402#hurt.siege.right.burden.permit"},
        headers=headers,
    )
    assert r.status_code == 200
    assert calls == ["ws://localhost:4402#hurt.siege.right.burden.permit"]
