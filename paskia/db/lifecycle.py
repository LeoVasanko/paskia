"""
Database lifecycle: initialization and maintenance.
"""

import asyncio
import logging
import os
import signal
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Optional
from uuid import UUID

from kanta import Kanta
from kanta.exceptions import DatabaseError

import paskia.db.operations as _ops
from paskia import oidc_notify
from paskia.authsession import EXPIRES
from paskia.db.bootstrap import bootstrap, log_reset_link
from paskia.db.paths import db_file_path
from paskia.db.structs import DB
from paskia.util.runtime import config as runtime_config

logger = logging.getLogger(__name__)


runtime = runtime_config()
if runtime is None:
    raise RuntimeError("PASKIA_CONFIG must be defined before importing db.lifecycle")

kanta = Kanta(
    str(db_file_path(rp_id=runtime.config.rp_id, create_root=False)),
    _ops._db,
    migrations="paskia.db.migrations",
)
kanta.ctx.rp_id = runtime.config.rp_id
_ops._db._store = kanta


def _lookup_uuid_in_state(state: dict | None, uuid_str: str) -> str | None:
    """Resolve UUID to label from serialized state dict."""
    if not state:
        return None

    # Display-name based entities.
    for bucket in ("users", "orgs", "roles", "permissions"):
        entity = state.get(bucket, {}).get(uuid_str)
        if isinstance(entity, dict):
            display_name = entity.get("display_name")
            if isinstance(display_name, str) and display_name:
                return display_name

    # OIDC clients use "name" instead of "display_name".
    client = state.get("oidc", {}).get("clients", {}).get(uuid_str)
    if isinstance(client, dict):
        name = client.get("name")
        if isinstance(name, str) and name:
            return name

    return None


def _resolve_uuid_label(
    uuid_str: str,
    *,
    previous: dict | None = None,
    current: dict | None = None,
) -> str | None:
    """Resolve known entity UUIDs to human-readable labels."""
    # Prefer previous state so deletions/renames still show a useful label.
    label = _lookup_uuid_in_state(previous, uuid_str)
    if label:
        return label
    label = _lookup_uuid_in_state(current, uuid_str)
    if label:
        return label

    try:
        uid = UUID(uuid_str)
    except ValueError:
        return None

    if uid in _ops._db.users:
        return _ops._db.users[uid].display_name
    if uid in _ops._db.orgs:
        return _ops._db.orgs[uid].display_name
    if uid in _ops._db.roles:
        return _ops._db.roles[uid].display_name
    if uid in _ops._db.permissions:
        return _ops._db.permissions[uid].display_name
    if uid in _ops._db.oidc.clients:
        return _ops._db.oidc.clients[uid].name
    return None


@kanta.logfmt
def format_log_uuid(
    value: Any,
    path: str,
    previous: Annotated[dict, "pre"] | None = None,
    current: Annotated[dict, "post"] | None = None,
) -> Optional[str]:  # noqa: UP045
    """Format UUID values/keys/actor labels in transaction logs."""
    if not isinstance(value, str):
        return None

    # Works for transaction actor metadata ($user), values, and path components.
    return _resolve_uuid_label(value, previous=previous, current=current)


@kanta.fatal_error
def terminate(error: DatabaseError) -> None:
    """Fatal error callback: terminate the process on background write failures."""
    logger.error("Fatal database error: %s", error)
    os.kill(os.getpid(), signal.SIGTERM)


@kanta.bootstrap
def bootstrap_db(data: DB) -> None:
    reset_passphrase = bootstrap(data, config=runtime.config)
    log_reset_link(reset_passphrase, "✅ Bootstrap completed!")


async def init():
    """Load database from JSONL file using kanta.

    If the database file is empty, the configured bootstrap callback seeds it
    with default permissions, organization, role, admin user and a reset token.
    """
    rootpath = Path(kanta.filename).parent
    try:
        await asyncio.to_thread(rootpath.mkdir, parents=True, exist_ok=True)
        await kanta.open()
    except Exception as e:
        raise SystemExit(f"{e}") from e


def cleanup_expired() -> int:
    """Remove expired sessions and reset tokens. Returns count removed."""
    now = datetime.now(UTC)
    limit = now - EXPIRES
    expired_sessions = [k for k, s in _ops._db.sessions.items() if s.validated < limit]
    if expired_sessions:
        oidc_notify.schedule_notifications(expired_sessions)
    with kanta.transaction("expiry"):
        for k in expired_sessions:
            del _ops._db.sessions[k]
        expired_tokens = [k for k, t in _ops._db.reset_tokens.items() if t.expiry < now]
        for k in expired_tokens:
            del _ops._db.reset_tokens[k]
    return len(expired_sessions) + len(expired_tokens)
