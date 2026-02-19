"""
Database lifecycle: initialization and maintenance.
"""

import logging
import os
from datetime import UTC, datetime

import paskia.db.operations as _ops
from paskia import oidc_notify
from paskia.authsession import EXPIRES
from paskia.db.jsonl import JsonlStore

_logger = logging.getLogger(__name__)


async def init(rp_id: str, *args, **kwargs):
    """Load database from JSONL file."""
    if _ops._db._store:
        _logger.debug("Database already initialized, skipping reload")
        return
    db_path = os.environ.get("PASKIA_DB", f"{rp_id}.paskiadb")
    store = JsonlStore(_ops._db, db_path)
    await store.load(db_path, rp_id=rp_id)
    _ops._db = store.db
    _ops._db._store = store
    # Request a snapshot after successful startup
    store._snapshot.request_force()


def cleanup_expired() -> int:
    """Remove expired sessions and reset tokens. Returns count removed."""
    now = datetime.now(UTC)
    count = 0
    limit = now - EXPIRES
    expired_sessions = [k for k, s in _ops._db.sessions.items() if s.validated < limit]
    if expired_sessions:
        oidc_notify.schedule_notifications(expired_sessions)
    with _ops._db.transaction("expiry"):
        for k in expired_sessions:
            del _ops._db.sessions[k]
            count += 1
        expired_tokens = [k for k, t in _ops._db.reset_tokens.items() if t.expiry < now]
        for k in expired_tokens:
            del _ops._db.reset_tokens[k]
            count += 1
    return count
