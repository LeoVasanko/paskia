"""Encrypted sync WebSocket: link registration, snapshots and live events.

Registration offers and handshake credentials live in RAM. Quantumpipe
replaces the one-time registration secret with a composite credential at its
atomic key-change point; only then is the new link persisted. Established
links resume with that credential. The application protocol above SecSocket
starts with a domain push, followed by snapshots, live events, session
write-backs and domain acknowledgements.
"""

import asyncio
import base64
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

import msgspec
from fastapi import WebSocket, WebSocketDisconnect
from quantumpipe import ProtocolError, SecSocket, generate_registration_secret

from paskia import db, syncfeed
from paskia.fastapi.strictapp import strict_app

_logger = logging.getLogger(__name__)

app = strict_app()

OFFER_TTL = 600  # registration offers live 10 minutes, RAM-only
_SYNC_AD = b"paskia-sync"


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
    link_id = secrets.token_urlsafe(12)
    secret = generate_registration_secret()
    _offers[link_id] = _Offer(secret, list(rp_ids), time.monotonic())
    encoded = base64.urlsafe_b64encode(secret).rstrip(b"=").decode()
    parts = urlsplit(base_url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return f"{scheme}://{link_id}:{encoded}@{parts.netloc}"


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


async def _send(sock: SecSocket, message: dict) -> None:
    await sock.send(syncfeed.encode(message))


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
    db.create_satellite_link(
        link_id,
        offer.rp_ids,
        sock.session.credential,
        label=(registration.get("label") or "")[:80],
    )
    return _Connection(ws=sock, link_id=link_id, scope=set(offer.rp_ids))


async def _apply_client_message(message: dict, conn: _Connection) -> None:
    """Satellite → upstream frames, confined to the link's scope."""
    mtype = message.get("type")
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
    try:
        conn = await _handshake(sock, store)
        if conn is None:
            return
        await _send(sock, {"type": "domains", "domains": domain_infos(conn.scope)})
        queue = syncfeed.subscribe(conn.scope)
        _connections[queue] = conn
        for table in syncfeed.TABLES:
            await _send(
                sock,
                {
                    "type": "snapshot",
                    "table": table,
                    "items": _snapshot_items(table, conn.scope),
                },
            )
        await _send(sock, {"type": "ready", "rp_ids": sorted(conn.scope)})

        sender = asyncio.create_task(_pump(sock, queue))
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
        if queue is not None:
            _connections.pop(queue, None)
            syncfeed.unsubscribe(queue)


async def _pump(sock: SecSocket, queue: asyncio.Queue) -> None:
    try:
        while True:
            await _send(sock, await queue.get())
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        pass
    except Exception:
        _logger.debug("Sync event pump ended", exc_info=True)
