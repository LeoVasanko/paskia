"""
Background task for database maintenance.

Periodically flushes pending changes to disk and cleans up expired items.
"""

import asyncio
import logging
from datetime import datetime, timezone

from paskia.db.jsonl import flush_changes

# Flush changes to disk every N seconds
FLUSH_INTERVAL = 1
# Cleanup expired items every N seconds (cheap when nothing to remove)
CLEANUP_INTERVAL = 1


_logger = logging.getLogger(__name__)
_background_task: asyncio.Task | None = None


def cleanup() -> None:
    """Remove expired sessions and reset tokens from the database."""
    from paskia.db.operations import _db

    if _db is None or _db._data is None:
        return

    with _db.transaction("expiry"):
        current_time = datetime.now(timezone.utc)

        # Clean expired sessions
        to_delete_sessions = [
            k for k, s in _db._data.sessions.items() if s.expiry < current_time
        ]
        for k in to_delete_sessions:
            del _db._data.sessions[k]

        # Clean expired reset tokens
        to_delete_tokens = [
            k for k, t in _db._data.reset_tokens.items() if t.expiry < current_time
        ]
        for k in to_delete_tokens:
            del _db._data.reset_tokens[k]


async def flush() -> None:
    """Write all pending database changes to disk."""
    import sys
    from paskia.db.operations import _db

    if _db is None:
        _logger.warning("flush() called but _db is None")
        print("[DB] flush() called but _db is None", file=sys.stderr)
        return
    pending_count = len(_db._pending_changes)
    if pending_count > 0:
        print(f"[DB] flush() called with {pending_count} pending changes, db_path={_db.db_path}", file=sys.stderr)
    await flush_changes(_db.db_path, _db._pending_changes)


async def _background_loop():
    """Background task that periodically flushes changes and cleans up."""
    import sys
    print("[DB] Background loop starting", file=sys.stderr)
    _logger.info("Background loop starting")
    # Run cleanup immediately on startup to clear old expired items
    cleanup()
    await flush()

    last_cleanup = datetime.now(timezone.utc)

    while True:
        try:
            await asyncio.sleep(FLUSH_INTERVAL)
            # Flush pending changes to disk
            await flush()

            # Run cleanup less frequently
            now = datetime.now(timezone.utc)
            if (now - last_cleanup).total_seconds() >= CLEANUP_INTERVAL:
                cleanup()
                await flush()  # Flush cleanup changes
                last_cleanup = now
        except asyncio.CancelledError:
            _logger.info("Background loop cancelled, final flush")
            # Final flush before exit
            await flush()
            break
        except Exception:
            _logger.exception("Error in database background loop")


async def start_background():
    """Start the background flush/cleanup task."""
    import sys
    global _background_task
    
    # Check if task exists but is no longer running (e.g., after uvicorn reload)
    if _background_task is not None:
        if _background_task.done():
            print(f"[DB] Previous background task was done, restarting", file=sys.stderr)
            _background_task = None
        else:
            # Task exists and is running - but might be in a dead event loop
            try:
                # Check if task is in current event loop
                loop = asyncio.get_running_loop()
                task_loop = _background_task.get_loop()
                if loop is not task_loop:
                    print(f"[DB] Background task in different event loop, restarting", file=sys.stderr)
                    _background_task = None
            except Exception as e:
                print(f"[DB] Error checking background task loop: {e}, restarting", file=sys.stderr)
                _background_task = None
    
    if _background_task is None:
        _background_task = asyncio.create_task(_background_loop())
        _logger.info("Database background task started")
        print("[DB] Database background task started", file=sys.stderr)
    else:
        print(f"[DB] Background task already running: {_background_task}", file=sys.stderr)


async def stop_background():
    """Stop the background task and flush any pending changes."""
    global _background_task
    if _background_task:
        _background_task.cancel()
        try:
            await _background_task
        except asyncio.CancelledError:
            pass
        _background_task = None


# Aliases for backwards compatibility
start_cleanup = start_background
stop_cleanup = stop_background
