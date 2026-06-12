"""
Background task for database maintenance.

Kanta handles periodic flushing to disk.  This module keeps a small
companion task that periodically cleans up expired sessions/tokens.
"""

import asyncio
import logging
import os
import signal

from kanta.exceptions import DatabaseError

import paskia.db.operations as _ops
from paskia.db.lifecycle import cleanup_expired

CLEANUP_INTERVAL = 1  # Expired item cleanup

_logger = logging.getLogger(__name__)
_background_task: asyncio.Task | None = None


def _sigterm_on_error(error: DatabaseError) -> None:
    """Exit the server when a database write fails."""
    _logger.error("Fatal database error: %s", error)
    os.kill(os.getpid(), signal.SIGTERM)


async def flush() -> None:
    """Write all pending database changes to disk."""
    store = _ops._store
    if store is None:
        _logger.warning("flush() called but _store is None")
        return
    try:
        await store.flush()
    except DatabaseError as e:
        _sigterm_on_error(e)


async def _background_loop():
    """Background task that periodically cleans up expired items."""
    # Run cleanup immediately on startup to clear old expired items
    cleanup_expired()

    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL)
            cleanup_expired()
        except asyncio.CancelledError:
            break
        except Exception:
            _logger.debug("Error in database background loop", exc_info=True)


async def start_background():
    """Start the background cleanup task."""
    global _background_task

    # Check if task exists but is no longer running (e.g., after uvicorn reload)
    if _background_task is not None:
        if _background_task.done():
            _logger.debug("Previous background task was done, restarting")
            _background_task = None
        else:
            # Task exists and is running - but might be in a dead event loop
            try:
                # Check if task is in current event loop
                loop = asyncio.get_running_loop()
                task_loop = _background_task.get_loop()
                if loop is task_loop:
                    # Task is already running in same loop - idempotent, just return
                    # This happens with dual IPv4+IPv6 endpoints sharing the same process
                    _logger.debug(
                        "Background task already running in same loop, skipping"
                    )
                    return
                _logger.debug("Background task in different event loop, restarting")
                _background_task = None
            except Exception as e:
                _logger.debug("Error checking background task loop: %s, restarting", e)
                _background_task = None

    if _background_task is None:
        _background_task = asyncio.create_task(_background_loop())


async def stop_background():
    """Stop the background cleanup task and close kanta."""
    global _background_task
    if _background_task:
        _background_task.cancel()
        try:
            await _background_task
        except asyncio.CancelledError:
            pass
        _background_task = None
    store = _ops._store
    if store is not None:
        try:
            await store.close()
        except DatabaseError as e:
            _sigterm_on_error(e)


# Aliases for backwards compatibility
start_cleanup = start_background
stop_cleanup = stop_background
