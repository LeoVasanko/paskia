"""RAM-only change feed letting satellite instances mirror this server.

Nothing here touches the database file: committed mutations are pushed to
connected satellites over the sync WebSocket (fastapi/sync.py). Satellites
authenticate with a token from the PASKIA_SYNC_TOKENS environment variable
(comma-separated); with the variable unset the sync endpoint stays closed.

There is deliberately no replay log: snapshots are small, so a reconnecting
satellite simply takes a fresh one.
"""

import asyncio
import os

import msgspec

# Tables mirrored by satellites (reset tokens, OIDC data and domain config
# are instance-local and never replicated).
TABLES = ("permissions", "orgs", "roles", "users", "credentials", "sessions")

_subscribers: set[asyncio.Queue] = set()


def emit(table: str, key: str, obj) -> None:
    """Publish an upsert (obj given) or delete (obj None) to subscribers."""
    if not _subscribers:
        return
    event = {
        "type": "event",
        "table": table,
        "key": key,
        "fields": msgspec.to_builtins(obj) if obj is not None else None,
    }
    for queue in list(_subscribers):
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            # Slow consumer: drop it; the client reconnects and resyncs.
            _subscribers.discard(queue)


def subscribe() -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers.add(queue)
    return queue


def unsubscribe(queue: asyncio.Queue) -> None:
    _subscribers.discard(queue)


def tokens_from_env() -> set[str]:
    """Accepted sync tokens (PASKIA_SYNC_TOKENS, comma-separated)."""
    return {
        t.strip()
        for t in os.environ.get("PASKIA_SYNC_TOKENS", "").split(",")
        if t.strip()
    }


def encode(message: dict) -> bytes:
    return msgspec.json.encode(message)
