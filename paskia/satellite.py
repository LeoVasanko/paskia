"""Satellite side of remote domains: RAM-only replicas + host dispatch.

Domains configured with ``DomainConfig.remote`` are backed by a remote
paskia instance. This module owns the whole feature: it resolves which
store serves a request host (local DB or the remote's read replica),
dispatches session writes (refresh write-behind, logout eviction), and
forwards requests the satellite cannot answer (exchange-code redemption,
OIDC, reset tokens) to the remote.

A replica is a plain DB instance, never persisted, fed by a sync
WebSocket (snapshot on connect, then live events) and swept for
expired sessions locally. While the channel is down the replica stays trusted for the
domain's cache_ttl, then reads fail with RemoteUnavailable (fail-closed;
a large cache_ttl gives fail-open behavior bounded by session expiry).
"""

import asyncio
import contextlib
import logging
import time
from datetime import UTC, datetime
from uuid import UUID

import httpx
import msgspec
import websockets
from fastapi import HTTPException, Request, Response

from paskia import db, domains
from paskia.config import SESSION_LIFETIME
from paskia.db.structs import (
    DB,
    Credential,
    Org,
    Permission,
    RemoteConfig,
    Role,
    Session,
    User,
)
from paskia.util.crypto import hash_secret

_logger = logging.getLogger(__name__)

_TABLES = {
    "permissions": (Permission, True),
    "orgs": (Org, True),
    "roles": (Role, True),
    "users": (User, True),
    "credentials": (Credential, True),
    "sessions": (Session, False),
}

_RECONNECT_DELAY = 5
_SWEEP_INTERVAL = 60


class RemoteReplica:
    """One remote instance's replica, its sync client and write-behind queue."""

    def __init__(self, remote: RemoteConfig):
        self.remote = remote
        self.db = DB()
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
            time.monotonic() - self.last_contact <= self.remote.cache_ttl
        )

    def refresh_session(
        self, key: str, validated: datetime, ip: str | None, user_agent: str | None
    ) -> None:
        """Apply a /validate refresh locally and queue it for the remote."""
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
        self._sweeper = asyncio.create_task(self._sweep())

    async def stop(self) -> None:
        self._stopped = True
        for task in (self._task, self._sweeper):
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

    async def _sweep(self) -> None:
        while True:
            await asyncio.sleep(_SWEEP_INTERVAL)
            limit = datetime.now(UTC) - SESSION_LIFETIME
            for key in [k for k, s in self.db.sessions.items() if s.validated < limit]:
                del self.db.sessions[key]

    async def _run(self) -> None:
        while not self._stopped:
            try:
                await self._connect()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _logger.info("Sync to %s failed: %s", self.remote.url, e)
            if self.connected:
                # The TTL clock starts when the feed goes down, not at the
                # last message — an idle connection is healthy.
                self.connected = False
                self.last_contact = time.monotonic()
            if not self._stopped:
                await asyncio.sleep(_RECONNECT_DELAY)

    async def _connect(self) -> None:
        ws_url = self.remote.url.replace("http", "ws", 1) + "/auth/api/sync/ws"
        async with websockets.connect(
            ws_url,
            additional_headers={"Authorization": f"Bearer {self.remote.token}"},
            # Prompt dead-peer detection: availability semantics count on it
            ping_interval=5,
            ping_timeout=5,
        ) as ws:
            sender = asyncio.create_task(self._send_loop(ws))
            staging: DB | None = None
            ready_at = 0.0
            try:
                while True:
                    if ready_at:
                        # Periodic reconnects give full-snapshot reconciliation
                        remaining = self.remote.refresh_interval - (
                            time.monotonic() - ready_at
                        )
                        if remaining <= 0:
                            return
                        try:
                            message = msgspec.json.decode(
                                await asyncio.wait_for(ws.recv(), remaining)
                            )
                        except TimeoutError:
                            return  # periodic resync: reconnect for a snapshot
                    else:
                        message = msgspec.json.decode(await ws.recv())
                    mtype = message.get("type")
                    if mtype == "snapshot":
                        staging = staging or DB()
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

    async def _send_loop(self, ws) -> None:
        while True:
            self._refresh_signal.clear()
            while self._pending_refresh:
                _, message = self._pending_refresh.popitem()
                await ws.send(msgspec.json.encode(message))
            await self._refresh_signal.wait()


def _apply(replica: DB, table: str, key: str, fields: dict | None) -> None:
    """Apply an upsert (fields given) or delete (fields None) to a replica."""
    cls, uuid_key = _TABLES[table]
    store = getattr(replica, table)
    store_key = UUID(key) if uuid_key else key
    if fields is None:
        store.pop(store_key, None)
        return
    obj = msgspec.convert(fields, cls)
    if uuid_key:
        obj.uuid = store_key
    else:
        obj.key = key
    store[store_key] = obj


class SatelliteManager:
    """Replicas keyed by remote URL; domains sharing a remote share one."""

    def __init__(self):
        self.replicas: dict[str, RemoteReplica] = {}

    async def start(self) -> None:
        domains.add_rebuild_listener(self.reconcile)
        await self.reconcile(domains.registry())

    async def stop(self) -> None:
        domains.remove_rebuild_listener(self.reconcile)
        for replica in self.replicas.values():
            await replica.stop()
        self.replicas.clear()
        for url in list(_clients):
            await _drop_client(url)

    async def reconcile(self, registry: domains.DomainRegistry) -> None:
        """Start/stop replicas to match the configured remote domains."""
        wanted = {}
        for domain in registry.domains:
            if domain.remote is not None:
                wanted.setdefault(domain.remote.url, domain.remote)
        for url in list(self.replicas):
            if url not in wanted:
                await self.replicas.pop(url).stop()
                await _drop_client(url)
        for url, remote in wanted.items():
            replica = self.replicas.get(url)
            if replica is None or replica.remote != remote:
                if replica is not None:
                    await replica.stop()
                replica = RemoteReplica(remote)
                self.replicas[url] = replica
                await replica.start()


manager = SatelliteManager()


# -------------------------------------------------------------------------
# Host-keyed dispatch: the only interface the rest of the app uses
# -------------------------------------------------------------------------


def replica_for_host(host: str | None) -> RemoteReplica | None:
    """The replica serving this host, or None for locally served hosts."""
    domain = domains.registry().resolve(host)
    if domain is None or domain.remote is None:
        return None
    return manager.replicas.get(domain.remote.url)


def store_for_host(host: str | None) -> DB:
    """The data store to read for a request host: the local database, or
    the replica of the remote backing the host's domain."""
    replica = replica_for_host(host)
    if replica is None:
        return db.data()
    if not replica.available():
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
        replica.db.sessions.pop(hash_secret("cookie", auth), None)


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
    """Close and forget the forwarding client for a remote URL."""
    client = _clients.pop(url, None)
    if client is not None:
        await client.aclose()


async def forward_request(request: Request) -> Response | None:
    """Forward the request to its domain's remote, or None when local.

    The original Host header is preserved so the remote dispatches to the
    same domain (sessions are host-bound). The user's cookie authenticates
    the forwarded call; the satellite needs no credentials of its own.
    """
    domain = domains.registry().resolve(request.headers.get("host"))
    if domain is None or domain.remote is None:
        return None
    url = domain.remote.url
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
