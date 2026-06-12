"""
Database lifecycle: initialization and maintenance.
"""

import logging
import os
import signal
from datetime import UTC, datetime

from kanta import Kanta
from kanta.exceptions import DatabaseError

import paskia.db.operations as _ops
from paskia import oidc_notify
from paskia.authsession import EXPIRES
from paskia.db.migrations import MigrationCtx
from paskia.db.paths import db_file_path
from paskia.db.structs import DB

_logger = logging.getLogger(__name__)


def _fatal_error(error: DatabaseError) -> None:
    """Fatal error callback: terminate the process on background write failures."""
    _logger.error("Fatal database error: %s", error)
    os.kill(os.getpid(), signal.SIGTERM)


async def init(rp_id: str, *args, **kwargs):
    """Load database from JSONL file using kanta."""
    if _ops._store is not None:
        _logger.debug("Database already initialized, skipping reload")
        return
    db_path = db_file_path(rp_id=rp_id, create_root=True)
    db = DB()
    kanta = Kanta(
        str(db_path),
        db,
        migrations="paskia.db.migrations",
        migration_ctx=MigrationCtx(rp_id=rp_id),
        fatal_error=_fatal_error,
    )
    try:
        await kanta.open()
    except DatabaseError as e:
        raise SystemExit(f"{e}") from e
    _ops._store = kanta
    _ops._db = db
    _ops._db._store = kanta
    # Request a snapshot after successful startup
    kanta.request_snapshot()


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
