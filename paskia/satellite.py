"""Satellite side of remote domains: uplinks, RAM-only replicas, dispatch.

A domain configured with ``DomainConfig.remote`` is backed by an upstream
paskia instance over a **link**: registered online through quantumpipe's
authenticated key exchange (one ``register_uplink`` path serves the admin UI
and the ``paskia satellite`` CLI), then kept up by a long-lived encrypted
connection per uplink. The upstream owns the domain set: it pushes the link's
domains (rp-id, display name, origins verbatim) on connect and whenever the
scope or a domain changes; the satellite validates them against its local
config, persists the accepted set, and reports rejections. Local edits of
remote domains are rejected — the only satellite-side configuration is
link creation and unlinking.

This module owns the rest of the feature: it resolves which store serves
a request host (local DB or an uplink's read replica), dispatches session
writes (refresh write-behind, logout eviction), and forwards requests the
satellite cannot answer (exchange-code redemption, OIDC, reset tokens,
session-less lookups like /check) to the upstream.

A replica is a ReplicaDB instance, never persisted, fed by the sync
channel (snapshot on connect, then live events) and swept for expired
sessions locally. The link's scope confines the replica to the pushed
domains' sessions and credentials, each session carrying the
ApiSessionContext the upstream computed for it (identity display data and
effective permissions for the session's host) — the user graph itself
never leaves the upstream. While the channel is down the replica stays
trusted for the uplink's cache_ttl, then reads fail closed (503; a large
cache_ttl gives fail-open behavior bounded by session expiry).
"""

import asyncio
import base64
import contextlib
import logging
import socket
import time
from datetime import UTC, datetime
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import UUID

import httpx
import msgspec
import websockets
from fastapi import HTTPException, Request, Response
from quantumpipe import ProtocolError, SecSocket

from paskia import db, domains, syncfeed
from paskia.config import SESSION_LIFETIME
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
    SessionContext,
    Uplink,
    User,
)
from paskia.util.apistructs import ApiSessionContext
from paskia.util.crypto import hash_secret

_logger = logging.getLogger(__name__)

_TABLES = {
    "credentials": (Credential, True),
    "sessions": (Session, False),
}

_RECONNECT_DELAY = 5
_SWEEP_INTERVAL = 60


class LinkRevokedError(Exception):
    """The upstream revoked the link; the satellite unlinks its side."""


class ReplicaDB(DB):
    """A sync replica's store: the uplink's sessions and credentials plus
    the per-session contexts (identity and effective permissions) the
    upstream pushes. Holds no user graph of its own; lookups join the
    session with its pushed context."""

    def __post_init__(self):
        super().__post_init__()
        self.session_contexts: dict[str, ApiSessionContext] = {}

    def session_ctx_for(self, s: Session, host: str | None) -> SessionContext | None:
        if s.client_uuid is not None or s.host != host:
            return None
        stored = self.session_contexts.get(s.key)
        if stored is None:
            return None
        try:
            credential = self.credentials[s.credential_uuid]
        except KeyError:
            return None
        user = User(
            display_name=stored.user.display_name,
            role_uuid=stored.role.uuid,
            created_at=s.validated,
            visits=0,
            theme=stored.user.theme,
        )
        user.uuid = stored.user.uuid
        role = Role(org_uuid=stored.org.uuid, display_name=stored.role.display_name)
        role.uuid = stored.role.uuid
        org = Org(display_name=stored.org.display_name)
        org.uuid = stored.org.uuid
        return SessionContext(
            session=s,
            user=user,
            org=org,
            role=role,
            credential=credential,
            permissions=[
                Permission(scope=scope, display_name=scope)
                for scope in stored.permissions
            ],
        )


def ws_url_for(base_url: str) -> str:
    """The upstream's sync WebSocket URL for an http(s) base URL."""
    return base_url.replace("http", "ws", 1) + "/auth/api/sync/ws"


def parse_link_url(url: str) -> tuple[str, str, bytes]:
    """Split ``wss://<link-id>:<registration-secret>@<host>`` into its parts."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("wss", "ws"):
        raise ValueError(
            "A link URL is a wss:// URL copied from the upstream's satellites panel"
        )
    link_id = unquote(parts.username or "")
    encoded = unquote(parts.password or "")
    if not link_id or not encoded:
        raise ValueError("The link URL carries no link id or registration key")
    try:
        secret = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError as e:
        raise ValueError("The link URL has a malformed registration key") from e
    if len(secret) != 32:
        raise ValueError("The link URL has a malformed registration key")
    netloc = parts.hostname or ""
    if not netloc:
        raise ValueError("The link URL carries no host")
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    scheme = "https" if parts.scheme == "wss" else "http"
    base = urlunsplit((scheme, netloc, parts.path, "", "")).rstrip("/")
    return base, link_id, secret


def _label() -> str:
    """This instance's self-reported name on links (informational)."""
    return socket.gethostname() or "satellite"


def _uplink_domains(uplink_id: str) -> dict[str, DomainConfig]:
    """The config domains currently served by an uplink."""
    return {
        rp_id: d
        for rp_id, d in db.data().config.domains.items()
        if d.remote is not None and d.remote.link == uplink_id
    }


def _accepted_domains(
    uplink_id: str, infos: list[dict]
) -> tuple[dict[str, DomainConfig], dict[str, str]]:
    """Validate a pushed domain set against the local configuration.

    The upstream is authoritative for the domains it pushes, but they must
    not collide with what this instance already serves: an rp-id served
    locally or by another uplink is rejected, as is a push that would break
    the merged config (e.g. an auth-host collision with a local domain).
    Returns (accepted, {rp_id: rejection reason}).
    """
    merged = {
        rp_id: d
        for rp_id, d in db.data().config.domains.items()
        if not (d.remote is not None and d.remote.link == uplink_id)
    }
    accepted: dict[str, DomainConfig] = {}
    rejected: dict[str, str] = {}
    for info in infos:
        rp_id = (info.get("rp_id") or "").strip().lower()
        if not rp_id:
            continue
        existing = db.data().config.domains.get(rp_id)
        if existing is not None and not (
            existing.remote is not None and existing.remote.link == uplink_id
        ):
            rejected[rp_id] = "served locally or by another uplink"
            continue
        try:
            origins = msgspec.convert(
                info.get("origins") or {}, dict[str, bool | OriginEntry]
            )
        except msgspec.ValidationError:
            rejected[rp_id] = "malformed origins"
            continue
        domain = DomainConfig(
            rp_name=info.get("rp_name") or None,
            origins=origins,
            remote=RemoteConfig(link=uplink_id),
        )
        try:
            domains.validate_config(
                Config(domains={**merged, **accepted, rp_id: domain})
            )
        except ValueError as e:
            rejected[rp_id] = str(e)
            continue
        accepted[rp_id] = domain
    return accepted, rejected


def _drop_replica_rows(replica: ReplicaDB, removed_rp_ids: set[str]) -> None:
    """Evict a removed domain's rows from a replica."""
    for key, s in list(replica.sessions.items()):
        if s.rp_id in removed_rp_ids:
            del replica.sessions[key]
            replica.session_contexts.pop(key, None)
    for cred_uuid, c in list(replica.credentials.items()):
        if c.rp_id in removed_rp_ids:
            del replica.credentials[cred_uuid]


def apply_domains_push(
    uplink_id: str, infos: list[dict], replica_db: ReplicaDB | None = None
) -> tuple[dict[str, str], bool]:
    """Apply a domain set pushed by the uplink: persist the accepted set
    (adding, updating and removing the link's domains) and rebuild the
    registry. Returns ({rp_id: rejection reason}, changed) — the rejections
    to report upstream, and whether the accepted set moved (the caller then
    resyncs: a newly added domain's existing sessions only arrive with a
    fresh snapshot)."""
    accepted, rejected = _accepted_domains(uplink_id, infos)
    current = _uplink_domains(uplink_id)
    changed = accepted != current
    if changed:
        db.apply_uplink_domains(uplink_id, accepted)
        domains.init_registry(db.data().config)
    if replica_db is not None and (removed := set(current) - set(accepted)):
        _drop_replica_rows(replica_db, removed)
    return rejected, changed


async def register_uplink(url: str) -> dict:
    """Register over quantumpipe, then persist the credential and domains."""
    base_url, link_id, initial_key = parse_link_url(url)
    if any(u.url == base_url for u in db.data().uplinks.values()):
        raise ValueError(f"Already linked to {base_url} — unlink first to re-register")
    try:
        async with websockets.connect(
            ws_url_for(base_url), ping_interval=5, ping_timeout=5
        ) as ws:
            store = {link_id: initial_key}
            sock = SecSocket(ws, store, link_id, ad=b"paskia-sync")
            await sock.connect()
            await sock.send(syncfeed.encode({"type": "register", "label": _label()}))
            pushed = msgspec.json.decode(await sock.receive())
            if pushed.get("type") != "domains":
                raise RuntimeError("the upstream did not complete the registration")
            accepted, rejected = _accepted_domains(link_id, pushed.get("domains") or [])
            await sock.send(
                syncfeed.encode({"type": "domains_ack", "rejected": rejected})
            )
            credential = sock.session.credential
    except (ProtocolError, websockets.exceptions.ConnectionClosed) as e:
        raise RuntimeError(
            "the upstream rejected the link URL (unknown or expired offer)"
        ) from e
    except TimeoutError as e:
        raise RuntimeError("the upstream did not answer in time") from e
    except RuntimeError:
        raise
    except Exception as e:
        raise RuntimeError(f"the upstream is unreachable: {e}") from e
    uplink = Uplink(url=base_url, created=datetime.now(UTC), key=credential)
    db.create_uplink(link_id, uplink, accepted)
    domains.init_registry(db.data().config)
    if manager.started:
        await manager.sync_uplinks()
    return {
        "link": link_id,
        "url": base_url,
        "domains": sorted(accepted),
        "rejected": rejected,
    }


class UplinkReplica:
    """One uplink's replica, its sync client and write-behind queue."""

    def __init__(self, uplink: Uplink):
        self.uplink = uplink  # uplink.uplink_id is set
        self.db = ReplicaDB()
        self.last_contact = 0.0  # monotonic time the feed last went down
        self.connected = False
        self._pending_refresh: dict[str, dict] = {}
        self._refresh_signal = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._sweeper: asyncio.Task | None = None
        self._stopped = True

    def available(self) -> bool:
        """Synced, and connected now or within cache_ttl of the disconnect."""
        if not self.last_contact:
            return False
        return self.connected or (
            time.monotonic() - self.last_contact <= self.uplink.cache_ttl
        )

    def refresh_session(
        self, key: str, validated: datetime, ip: str | None, user_agent: str | None
    ) -> None:
        """Apply a /validate refresh locally and queue it for the upstream."""
        session = self.db.sessions.get(key)
        if session is not None:
            session.validated = validated
            if ip is not None:
                session.ip = ip
            if user_agent is not None:
                session.user_agent = user_agent
        self._pending_refresh[key] = {
            "type": "session_refresh",
            "key": key,
            "validated": msgspec.to_builtins(validated),
            "ip": ip,
            "user_agent": user_agent,
        }
        self._refresh_signal.set()

    async def start(self) -> None:
        self._stopped = False
        self._task = asyncio.create_task(self._run())
        self._task.add_done_callback(lambda t: _replica_done(self, t))
        self._sweeper = asyncio.create_task(self._sweep())

    async def stop(self) -> None:
        self._stopped = True
        for task in (self._task, self._sweeper):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError, LinkRevokedError):
                    await task

    async def _sweep(self) -> None:
        while True:
            await asyncio.sleep(_SWEEP_INTERVAL)
            limit = datetime.now(UTC) - SESSION_LIFETIME
            for key in [k for k, s in self.db.sessions.items() if s.validated < limit]:
                del self.db.sessions[key]
                self.db.session_contexts.pop(key, None)

    async def _run(self) -> None:
        while not self._stopped:
            try:
                await self._connect()
            except asyncio.CancelledError:
                raise
            except LinkRevokedError:
                raise  # the manager unlinks via the done-callback
            except Exception as e:
                _logger.info("Sync to %s failed: %s", self.uplink.url, e)
            if self.connected:
                # The TTL clock starts when the feed goes down, not at the
                # last message — an idle connection is healthy.
                self.connected = False
                self.last_contact = time.monotonic()
            if not self._stopped:
                await asyncio.sleep(_RECONNECT_DELAY)

    async def _recv(self, sock: SecSocket, timeout: float | None = None) -> dict:
        try:
            if timeout is None:
                message = await sock.receive()
            else:
                message = await asyncio.wait_for(sock.receive(), timeout)
            return msgspec.json.decode(message)
        except websockets.exceptions.ConnectionClosed as e:
            if e.code == 1008:
                raise LinkRevokedError(self.uplink.url) from e
            raise

    async def _connect(self) -> None:
        async with websockets.connect(
            ws_url_for(self.uplink.url),
            # Prompt dead-peer detection: availability semantics count on it
            ping_interval=5,
            ping_timeout=5,
        ) as ws:
            store = {self.uplink.uplink_id: self.uplink.key}
            sock = SecSocket(ws, store, self.uplink.uplink_id, ad=b"paskia-sync")
            try:
                await sock.connect()
            except websockets.exceptions.ConnectionClosed as e:
                if e.code == 1008:
                    raise LinkRevokedError(self.uplink.url) from e
                raise
            # Every connection starts with the authoritative domain set.
            pushed = await self._recv(sock)
            if pushed.get("type") != "domains":
                raise ValueError("sync: protocol error (expected domains)")
            rejected, _ = apply_domains_push(
                self.uplink.uplink_id, pushed.get("domains") or [], replica_db=self.db
            )
            await sock.send(syncfeed.encode({"type": "domains_ack", "rejected": rejected}))

            sender = asyncio.create_task(self._send_loop(sock))
            staging: ReplicaDB | None = None
            ready_at = 0.0
            try:
                while True:
                    if ready_at:
                        # Periodic reconnects give full-snapshot reconciliation
                        remaining = self.uplink.refresh_interval - (
                            time.monotonic() - ready_at
                        )
                        if remaining <= 0:
                            return
                        try:
                            message = await self._recv(sock, remaining)
                        except TimeoutError:
                            return  # periodic resync: reconnect for a snapshot
                    else:
                        message = await self._recv(sock)
                    mtype = message.get("type")
                    if mtype == "snapshot":
                        staging = staging or ReplicaDB()
                        for key, fields in message["items"]:
                            _apply(staging, message["table"], key, fields)
                    elif mtype == "event":
                        if staging is not None:
                            raise ValueError("sync: event before ready")
                        _apply(
                            self.db,
                            message["table"],
                            message["key"],
                            message.get("fields"),
                        )
                    elif mtype == "domains":
                        # A changed domain set needs a fresh snapshot.
                        rejected, changed = apply_domains_push(
                            self.uplink.uplink_id,
                            message.get("domains") or [],
                            replica_db=self.db,
                        )
                        await sock.send(
                            syncfeed.encode(
                                {"type": "domains_ack", "rejected": rejected}
                            )
                        )
                        if changed:
                            return
                    elif mtype == "ready":
                        if staging is not None:
                            self.db = staging
                            staging = None
                        self.connected = True
                        self.last_contact = ready_at = time.monotonic()
            finally:
                sender.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await sender

    async def _send_loop(self, sock: SecSocket) -> None:
        while True:
            self._refresh_signal.clear()
            while self._pending_refresh:
                _, message = self._pending_refresh.popitem()
                await sock.send(syncfeed.encode(message))
            await self._refresh_signal.wait()


def _replica_done(replica: UplinkReplica, task: asyncio.Task) -> None:
    """A replica's loop ended: a revocation (the only way out besides
    cancellation) unlinks the satellite side."""
    if task.cancelled():
        return
    exc = task.exception()
    if not isinstance(exc, LinkRevokedError):
        return
    _logger.info("Uplink %s revoked the link — unlinking", replica.uplink.url)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(manager.unlink(replica.uplink.uplink_id))


def _apply(replica: ReplicaDB, table: str, key: str, fields: dict | None) -> None:
    """Apply an upsert (fields given) or delete (fields None) to a replica.
    Session upserts carry their upstream-computed context as ``ctx``."""
    cls, uuid_key = _TABLES[table]
    store = getattr(replica, table)
    store_key = UUID(key) if uuid_key else key
    if fields is None:
        store.pop(store_key, None)
        if table == "sessions":
            replica.session_contexts.pop(key, None)
        return
    fields = dict(fields)
    ctx = fields.pop("ctx", None) if table == "sessions" else None
    obj = msgspec.convert(fields, cls)
    if uuid_key:
        obj.uuid = store_key
    else:
        obj.key = key
    store[store_key] = obj
    if table == "sessions":
        if ctx is not None:
            replica.session_contexts[key] = msgspec.convert(ctx, ApiSessionContext)
        else:
            replica.session_contexts.pop(key, None)


class SatelliteManager:
    """Replicas keyed by uplink id; one connection per uplink carries all
    of the link's domains."""

    def __init__(self):
        self.replicas: dict[str, UplinkReplica] = {}
        self.started = False

    async def start(self) -> None:
        self.started = True
        await self.sync_uplinks()

    async def stop(self) -> None:
        self.started = False
        for replica in self.replicas.values():
            await replica.stop()
        self.replicas.clear()
        for url in list(_clients):
            await _drop_client(url)

    async def sync_uplinks(self) -> None:
        """Start/stop replicas to match the stored uplinks."""
        wanted = db.data().uplinks
        for uplink_id in list(self.replicas):
            if uplink_id not in wanted:
                replica = self.replicas.pop(uplink_id)
                await replica.stop()
                await _drop_client(replica.uplink.url)
        # Snapshot: a revocation task may mutate the uplinks mid-loop
        for uplink_id, uplink in list(wanted.items()):
            uplink.uplink_id = uplink_id  # fresh objects lack it until load
            replica = self.replicas.get(uplink_id)
            if replica is None or replica.uplink != uplink:
                if replica is not None:
                    await replica.stop()
                replica = UplinkReplica(uplink)
                self.replicas[uplink_id] = replica
                await replica.start()

    async def unlink(self, uplink_id: str) -> None:
        """Drop an uplink and every domain it serves (admin unlink, or the
        upstream revoked the link)."""
        replica = self.replicas.pop(uplink_id, None)
        if replica is not None:
            await replica.stop()
            await _drop_client(replica.uplink.url)
        db.delete_uplink(uplink_id)
        domains.init_registry(db.data().config)


manager = SatelliteManager()


# -------------------------------------------------------------------------
# Host-keyed dispatch: the only interface the rest of the app uses
# -------------------------------------------------------------------------


def replica_for_host(host: str | None) -> UplinkReplica | None:
    """The replica serving this host, or None for locally served hosts."""
    domain = domains.registry().resolve(host)
    if domain is None or domain.remote is None:
        return None
    return manager.replicas.get(domain.remote.link)


def store_for_host(host: str | None) -> DB:
    """The data store to read for a request host: the local database, or
    the replica of the uplink backing the host's domain."""
    domain = domains.registry().resolve(host)
    if domain is None or domain.remote is None:
        return db.data()
    replica = manager.replicas.get(domain.remote.link)
    if replica is None or not replica.available():
        raise HTTPException(503, "Remote authentication service unavailable")
    return replica.db


def refresh_session(
    key: str,
    host: str | None,
    ip: str | None,
    user_agent: str | None,
    validated: datetime,
    ctx=None,
):
    """/validate refresh: write-behind for remote domains, else local DB."""
    replica = replica_for_host(host)
    if replica is not None:
        replica.refresh_session(key, validated, ip, user_agent)
    else:
        db.update_session(
            key, ip=ip, user_agent=user_agent, validated=validated, ctx=ctx
        )


def evict_session(auth: str, host: str | None) -> None:
    """Drop a session from the replica (its remote deletion arrives via sync)."""
    replica = replica_for_host(host)
    if replica is not None:
        key = hash_secret("cookie", auth)
        replica.db.sessions.pop(key, None)
        replica.db.session_contexts.pop(key, None)


_TIMEOUT = httpx.Timeout(15.0, connect=5.0)

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "accept-encoding",
    "content-encoding",
}

_clients: dict[str, httpx.AsyncClient] = {}


async def _drop_client(url: str) -> None:
    """Close and forget the forwarding client for an uplink URL."""
    client = _clients.pop(url, None)
    if client is not None:
        await client.aclose()


def _uplink_url(domain: domains.Domain) -> str:
    """The base URL of the uplink backing a remote domain (503 if the
    config and the uplinks table desynced — a bug, not a local answer)."""
    uplink = db.data().uplinks.get(domain.remote.link)
    if uplink is None:
        raise HTTPException(503, "Remote authentication service unavailable")
    return uplink.url


async def forward_request(request: Request) -> Response | None:
    """Forward the request to its domain's uplink, or None when local.

    The original Host header is preserved so the upstream dispatches to the
    same domain (sessions are host-bound). The user's cookie authenticates
    the forwarded call; the satellite needs no credentials of its own.
    """
    domain = domains.registry().resolve(request.headers.get("host"))
    if domain is None or domain.remote is None:
        return None
    url = _uplink_url(domain)
    client = _clients.get(url)
    if client is None:
        client = _clients[url] = httpx.AsyncClient(base_url=url, timeout=_TIMEOUT)
    try:
        upstream = await client.request(
            request.method,
            request.url.path,
            params=request.url.query,
            content=await request.body(),
            headers={
                k: v for k, v in request.headers.items() if k.lower() not in _HOP_BY_HOP
            },
        )
    except httpx.TransportError as e:
        raise HTTPException(503, "Remote authentication service unavailable") from e
    response = Response(content=upstream.content, status_code=upstream.status_code)
    # Raw headers to preserve repeated Set-Cookie
    response.raw_headers = [
        (k, v) for k, v in upstream.headers.raw if k.decode().lower() not in _HOP_BY_HOP
    ]
    return response
