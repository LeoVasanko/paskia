"""RAM-only change feed letting satellite instances mirror this server.

Nothing here touches the database file: committed mutations are pushed to
connected satellites over the sync WebSocket (fastapi/sync.py). Satellites
authenticate with a link credential created at registration (stored in the
database, scoped to the link's rp-ids); a scoped subscription receives only
its own rp-ids' sessions and credentials — never the user graph. The scope
set is live: adjusting the link's scope mutates it in place.

Data minimization is per session: every session upsert carries an embedded
``ctx`` (the ApiSessionContext also sent to users) holding the session's
user/org/role display data and effective permissions, computed for the
session's bound host. Mutations of the user graph (users, orgs, roles,
permissions) are not published; instead they trigger an eager re-push of
the affected sessions with freshly computed contexts, so revocations and
renames reach satellites within one RTT.

There is deliberately no replay log: snapshots are small, so a reconnecting
satellite simply takes a fresh one.
"""

import asyncio
from uuid import UUID

import msgspec

# Tables mirrored by satellites, all filtered to the subscriber's rp-id
# scope set (reset tokens, link tables, OIDC data and domain config are
# instance-local and never replicated).
TABLES = ("credentials", "sessions")


# The user graph is never published; upserts of these tables drive the
# eager re-push of affected session contexts instead.
_GRAPH_TABLES = ("permissions", "orgs", "roles", "users")

_subscribers: dict[asyncio.Queue, set[str] | None] = {}


def session_ctx_dict(session) -> dict | None:
    """The session's ApiSessionContext as builtins (embedded in session
    events and snapshots), computed for the session's bound host."""
    from paskia import db  # noqa: PLC0415 (import cycle)
    from paskia.util import userinfo  # noqa: PLC0415 (import cycle)

    data = db.data()
    if data is None:
        return None
    ctx = data.session_ctx_for(session, session.host)
    if ctx is None:
        return None
    return msgspec.to_builtins(userinfo.build_session_context(ctx))


def _repush_contexts(table: str, key: str) -> None:
    """Re-emit the sessions whose context a user-graph upsert may have
    changed: each carries a freshly computed ctx. Deletions are not needed
    here — those cascade as session/credential delete events."""
    from paskia import db  # noqa: PLC0415 (import cycle)

    data = db.data()
    if data is None:
        return
    uuid = UUID(key)
    if table == "users":
        affected = {uuid}
    elif table == "roles":
        affected = {u.uuid for u in data.users.values() if u.role_uuid == uuid}
    elif table == "orgs":
        affected = {
            u.uuid
            for u in data.users.values()
            if data.roles.get(u.role_uuid) is not None
            and data.roles[u.role_uuid].org_uuid == uuid
        }
    else:  # permissions: roles containing it, then their users
        affected = {
            u.uuid
            for u in data.users.values()
            if (role := data.roles.get(u.role_uuid)) is not None
            and uuid in role.permissions
        }
    for skey, session in data.sessions.items():
        if session.user_uuid in affected:
            emit("sessions", skey, session)


def emit(table: str, key: str, obj) -> None:
    """Publish an upsert (obj given) or delete (obj None) to subscribers."""
    if not _subscribers:
        return
    if table in _GRAPH_TABLES:
        # The user graph stays on the master; its changes reach satellites
        # as re-pushed session contexts.
        if obj is not None:
            _repush_contexts(table, key)
        return
    fields = msgspec.to_builtins(obj) if obj is not None else None
    if table == "sessions" and obj is not None:
        fields["ctx"] = session_ctx_dict(obj)
    event = {"type": "event", "table": table, "key": key, "fields": fields}
    for queue, scope in list(_subscribers.items()):
        if (
            scope is not None
            and table in TABLES
            and fields is not None
            and fields.get("rp_id") not in scope
        ):
            # Out of scope upsert; deletes pass (a replica ignores unknown
            # keys, and the deleted object no longer tells its rp-id).
            continue
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            # Slow consumer: drop it; the client reconnects and resyncs.
            _subscribers.pop(queue, None)


def subscribe(scope: set[str] | None = None) -> asyncio.Queue:
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    _subscribers[queue] = scope
    return queue


def unsubscribe(queue: asyncio.Queue) -> None:
    _subscribers.pop(queue, None)


def encode(message: dict) -> bytes:
    return msgspec.json.encode(message)


def decode_bytes(value: bytes | str) -> bytes:
    return msgspec.convert(value, bytes)
