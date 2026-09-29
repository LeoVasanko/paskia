"""Sync WebSocket endpoint: serves snapshots and live events to satellites.

Token-gated via PASKIA_SYNC_TOKENS (env); closed when unset. All state is
RAM-only (syncfeed); the database schema is untouched. Protocol: snapshot
chunks per table, `ready`, then live upsert/delete events; the client sends
session_refresh write-backs. Reconnects always restart from a snapshot.
"""

import asyncio
import logging
from datetime import datetime

import msgspec
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from paskia import db, syncfeed

_logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


async def _send(ws: WebSocket, message: dict) -> None:
    await ws.send_bytes(syncfeed.encode(message))


async def _apply_client_message(message: dict) -> None:
    """Satellite write-behind: session refresh (validated/ip/user-agent)."""
    if message.get("type") != "session_refresh":
        return
    key = message.get("key") or ""
    session = db.data().sessions.get(key)
    if session is None:
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
    tokens = syncfeed.tokens_from_env()
    auth = ws.headers.get("authorization", "")
    if not tokens or auth.removeprefix("Bearer ").strip() not in tokens:
        await ws.close(code=1008)
        return
    await ws.accept()

    queue = syncfeed.subscribe()
    try:
        data = db.data()
        for table in syncfeed.TABLES:
            await _send(
                ws,
                {
                    "type": "snapshot",
                    "table": table,
                    "items": [
                        [str(key), msgspec.to_builtins(obj)]
                        for key, obj in getattr(data, table).items()
                    ],
                },
            )
        await _send(ws, {"type": "ready"})

        sender = asyncio.create_task(_pump(ws, queue))
        try:
            while True:
                await _apply_client_message(
                    msgspec.json.decode(await ws.receive_bytes())
                )
        finally:
            sender.cancel()
    except WebSocketDisconnect:
        pass
    except Exception:
        _logger.exception("Sync WebSocket failed")
    finally:
        syncfeed.unsubscribe(queue)


async def _pump(ws: WebSocket, queue: asyncio.Queue) -> None:
    try:
        while True:
            await _send(ws, await queue.get())
    except WebSocketDisconnect, RuntimeError, asyncio.CancelledError:
        pass
    except Exception:
        _logger.debug("Sync event pump ended", exc_info=True)
