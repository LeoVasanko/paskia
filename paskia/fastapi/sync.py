"""Encrypted sync WebSocket: link registration, snapshots and live events.

Registration offers and handshake credentials live in RAM. Quantumpipe
replaces the one-time registration secret with a composite credential at its
atomic key-change point; only then is the new link persisted. Established
links resume with that credential. The application protocol above SecSocket
starts with a domain push, followed by snapshots, live events, session
write-backs, domain acknowledgements, and allowlisted ASGI exchanges.
"""

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

import msgspec
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from quantumpipe import ProtocolError, SecSocket

from paskia import db, domains, syncfeed
from paskia.fastapi.strictapp import strict_app
from paskia.util.passphrase import derive_registration_secret, generate

_logger = logging.getLogger(__name__)

app = strict_app()

OFFER_TTL = 600  # registration offers live 10 minutes, RAM-only
_SYNC_AD = b"paskia-sync"
_FORWARDED_PATHS = {
    "/auth/api/check",
    "/auth/api/user-info",
    "/auth/api/token-info",
    "/auth/api/logout",
    "/auth/api/set-session",
}
_FORWARDED_PREFIXES = ("/auth/api/user/", "/auth/oidc/")
_asgi_app = None


def set_asgi_app(application) -> None:
    global _asgi_app
    _asgi_app = application


@dataclass
class _Offer:
    secret: bytes
    rp_ids: list[str]
    created: float  # monotonic


@dataclass
class _Connection:
    """One live link connection: its secured WebSocket, link id, live feed
    scope and the satellite's latest domain rejections."""

    ws: SecSocket
    link_id: str
    scope: set[str]
    rejected: dict[str, str] = field(default_factory=dict)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    requests: set[asyncio.Task] = field(default_factory=set)


_offers: dict[str, _Offer] = {}
_connections: dict[asyncio.Queue, _Connection] = {}


def _sweep_offers() -> None:
    now = time.monotonic()
    for link_id, offer in list(_offers.items()):
        if now - offer.created > OFFER_TTL:
            _offers.pop(link_id, None)


class _HandshakeStore(dict):
    """Per-connection credentials; offer spending follows quantumpipe's swap."""

    def __init__(self):
        _sweep_offers()
        super().__init__((link_id, offer.secret) for link_id, offer in _offers.items())
        self.update(
            (link_id, link.key) for link_id, link in db.data().satellite_links.items()
        )
        self.registered_offer: _Offer | None = None

    def __setitem__(self, link_id: str, credential: bytes) -> None:
        previous = self.get(link_id)
        if previous is not None and len(previous) == 32 and len(credential) != 32:
            offer = _offers.get(link_id)
            if offer is None or not secrets.compare_digest(offer.secret, previous):
                raise ProtocolError("registration key already spent")
            _offers.pop(link_id, None)
            self.registered_offer = offer
        super().__setitem__(link_id, credential)

    def __delitem__(self, link_id: str) -> None:
        previous = self.get(link_id)
        if previous is not None and len(previous) == 32:
            offer = _offers.get(link_id)
            if offer is not None and secrets.compare_digest(offer.secret, previous):
                _offers.pop(link_id, None)
        super().__delitem__(link_id)


def create_offer(rp_ids: list[str], base_url: str) -> str:
    """Mint a RAM-only registration offer; returns the wss link URL."""
    _sweep_offers()
    offer_id = secrets.token_urlsafe(12)
    secret = generate()
    _offers[offer_id] = _Offer(
        derive_registration_secret(secret), list(rp_ids), time.monotonic()
    )
    parts = urlsplit(base_url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return f"{scheme}://{parts.netloc}#{secret}"


def links_status() -> dict[str, dict]:
    """Live state per link id for the admin API."""
    status: dict[str, dict] = {}
    for conn in _connections.values():
        entry = status.setdefault(conn.link_id, {"connected": True, "rejected": {}})
        entry["rejected"].update(conn.rejected)
    return status


async def close_link(link_id: str) -> None:
    """Drop a link's live connections (revocation)."""
    for conn in list(_connections.values()):
        if conn.link_id == link_id:
            with contextlib.suppress(Exception):
                await conn.ws.close(code=1008)


def domain_infos(rp_ids) -> list[dict]:
    """The pushed configuration of each in-scope domain."""
    infos = []
    for rp_id in rp_ids:
        domain = db.data().config.domains.get(rp_id)
        if domain is None or domain.remote is not None:
            continue
        infos.append(
            {
                "rp_id": rp_id,
                "rp_name": domain.rp_name or "",
                "origins": msgspec.to_builtins(domain.origins),
            }
        )
    return infos


def push_link_domains(link_id: str) -> None:
    """Queue the link's current domain set and update live feed scopes."""
    link = db.data().satellite_links.get(link_id)
    if link is None:
        return
    message = {"type": "domains", "domains": domain_infos(link.rp_ids)}
    for queue, conn in list(_connections.items()):
        if conn.link_id != link_id:
            continue
        conn.scope.clear()
        conn.scope.update(link.rp_ids)
        try:
            queue.put_nowait(message)
        except asyncio.QueueFull:
            _connections.pop(queue, None)
            syncfeed.unsubscribe(queue)


def refresh_links_serving(rp_id: str) -> None:
    """A domain changed upstream: push its updated info to links serving it."""
    for link_id, link in db.data().satellite_links.items():
        if rp_id in link.rp_ids:
            push_link_domains(link_id)


def drop_domain_from_links(rp_id: str, *, ctx=None) -> None:
    """A domain was deleted upstream: shrink every link's scope and push."""
    for link_id, link in db.data().satellite_links.items():
        if rp_id in link.rp_ids:
            db.set_satellite_link_scope(
                link_id, [r for r in link.rp_ids if r != rp_id], ctx=ctx
            )
            push_link_domains(link_id)


async def _send(conn: _Connection, message: dict) -> None:
    async with conn.send_lock:
        await conn.ws.send(syncfeed.encode(message))


async def _receive(sock: SecSocket) -> dict:
    message = await sock.receive()
    if not isinstance(message, bytes | str):
        raise ProtocolError("expected a JSON sync frame")
    return msgspec.json.decode(message)


def _snapshot_items(table: str, scope: set[str]) -> list:
    """Snapshot rows for a table, filtered to the link's rp-id scope."""
    items = []
    for key, obj in getattr(db.data(), table).items():
        if obj.rp_id not in scope:
            continue
        fields = msgspec.to_builtins(obj)
        if table == "sessions":
            fields["ctx"] = syncfeed.session_ctx_dict(obj)
        items.append([str(key), fields])
    return items


async def _handshake(sock: SecSocket, store: _HandshakeStore) -> _Connection | None:
    """Establish the secure channel and commit first-time registration."""
    await sock.accept()
    link_id = sock.session.link_id
    if not sock.session.registering:
        link = db.data().satellite_links[link_id]
        return _Connection(ws=sock, link_id=link_id, scope=set(link.rp_ids))

    offer = store.registered_offer
    if offer is None:
        raise ProtocolError("registration offer missing after key change")
    registration = await _receive(sock)
    if registration.get("type") != "register":
        await sock.close(code=1008)
        return None
    link_id = secrets.token_urlsafe(12)
    db.create_satellite_link(
        link_id,
        offer.rp_ids,
        sock.session.credential,
        label=(registration.get("label") or "")[:80],
    )
    return _Connection(ws=sock, link_id=link_id, scope=set(offer.rp_ids))


def _forwarded_scope(message: dict) -> dict:
    source = message.get("scope") or {}
    path = source.get("path") or ""
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": source.get("http_version", "1.1"),
        "method": source.get("method", "GET"),
        "scheme": source.get("scheme", "https"),
        "path": path,
        "raw_path": syncfeed.decode_bytes(source.get("raw_path", path.encode())),
        "query_string": syncfeed.decode_bytes(source.get("query_string", b"")),
        "root_path": "",
        "headers": [
            (syncfeed.decode_bytes(k), syncfeed.decode_bytes(v))
            for k, v in source.get("headers", [])
        ],
        "client": source.get("client"),
        "server": None,
        "paskia.forwarded": True,
    }


def _forwarded_domain(scope: dict) -> domains.Domain | None:
    host = next(
        (
            value.decode("latin-1")
            for name, value in scope["headers"]
            if name.lower() == b"host"
        ),
        None,
    )
    return domains.registry().resolve(host)


def _path_allowed(path: str) -> bool:
    return path in _FORWARDED_PATHS or path.startswith(_FORWARDED_PREFIXES)


async def _run_asgi(message: dict, conn: _Connection) -> None:
    call_id = message.get("id") or ""
    started = False

    async def send(asgi_message: dict) -> None:
        nonlocal started
        if asgi_message["type"] == "http.response.start":
            started = True
        await _send(conn, {**asgi_message, "id": call_id})

    body = b""
    received = False

    async def receive() -> dict:
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    scope = None
    try:
        body = syncfeed.decode_bytes(message.get("body", b""))
        scope = _forwarded_scope(message)
        domain = _forwarded_domain(scope)
        if domain is None or domain.rp_id not in conn.scope:
            response = PlainTextResponse(
                "Host outside satellite link scope", status_code=421
            )
            await response(scope, receive, send)
        elif not _path_allowed(scope["path"]):
            response = PlainTextResponse("Path not allowed for satellites", status_code=403)
            await response(scope, receive, send)
        elif _asgi_app is None:
            raise RuntimeError("ASGI application is not configured")
        else:
            await _asgi_app(scope, receive, send)
    except Exception:
        _logger.exception("Forwarded ASGI request failed")
        try:
            if started or scope is None:
                await _send(conn, {"type": "asgi.error", "id": call_id})
            else:
                response = PlainTextResponse(
                    "Forwarded request failed", status_code=500
                )
                await response(scope, receive, send)
        except Exception:
            _logger.debug("Could not report forwarded ASGI failure", exc_info=True)


def _start_asgi(message: dict, conn: _Connection) -> None:
    task = asyncio.create_task(_run_asgi(message, conn))
    conn.requests.add(task)
    task.add_done_callback(conn.requests.discard)


async def _apply_client_message(message: dict, conn: _Connection) -> None:
    """Satellite → upstream frames, confined to the link's scope."""
    mtype = message.get("type")
    if mtype == "http.request":
        _start_asgi(message, conn)
        return
    if mtype == "domains_ack":
        conn.rejected = message.get("rejected") or {}
        return
    if mtype != "session_refresh":
        return
    key = message.get("key") or ""
    session = db.data().sessions.get(key)
    if session is None or session.rp_id not in conn.scope:
        return
    try:
        validated = msgspec.convert(message.get("validated"), datetime)
    except msgspec.ValidationError:
        return
    db.update_session(
        key,
        ip=message.get("ip") or None,
        user_agent=message.get("user_agent") or None,
        validated=validated,
    )


@app.websocket("/ws")
async def sync_websocket(ws: WebSocket):
    store = _HandshakeStore()
    sock = SecSocket(ws, store, ad=_SYNC_AD)
    queue: asyncio.Queue | None = None
    conn: _Connection | None = None
    try:
        conn = await _handshake(sock, store)
        if conn is None:
            return
        await _send(
            conn,
            {
                "type": "domains",
                "link": conn.link_id,
                "domains": domain_infos(conn.scope),
            },
        )
        queue = syncfeed.subscribe(conn.scope)
        _connections[queue] = conn
        for table in syncfeed.TABLES:
            await _send(
                conn,
                {
                    "type": "snapshot",
                    "table": table,
                    "items": _snapshot_items(table, conn.scope),
                },
            )
        await _send(conn, {"type": "ready", "rp_ids": sorted(conn.scope)})

        sender = asyncio.create_task(_pump(conn, queue))
        try:
            while True:
                await _apply_client_message(await _receive(sock), conn)
        finally:
            sender.cancel()
    except (WebSocketDisconnect, RuntimeError, ProtocolError, TimeoutError):
        pass
    except Exception:
        _logger.exception("Sync WebSocket failed")
    finally:
        if conn is not None:
            requests = list(conn.requests)
            for task in requests:
                task.cancel()
            await asyncio.gather(*requests, return_exceptions=True)
        if queue is not None:
            _connections.pop(queue, None)
            syncfeed.unsubscribe(queue)


async def _pump(conn: _Connection, queue: asyncio.Queue) -> None:
    try:
        while True:
            await _send(conn, await queue.get())
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass
    except Exception:
        _logger.debug("Sync event pump ended", exc_info=True)
