"""
Background task for database maintenance.

Periodically flushes pending changes to disk and cleans up expired items.
"""

import asyncio
import logging
from datetime import UTC, datetime

import paskia.db.operations as _ops
from paskia.db.lifecycle import cleanup_expired

FLUSH_INTERVAL = 0.1  # Flush to disk
CLEANUP_INTERVAL = 1  # Expired item cleanup


_logger = logging.getLogger(__name__)
_background_task: asyncio.Task | None = None


async def flush() -> None:
    """Write all pending database changes to disk."""
    store = _ops._store
    if store is None:
        _logger.warning("flush() called but _store is None")
        return
    await store.flush()


async def _background_loop():
    """Background task that periodically flushes changes and cleans up."""
    # Run cleanup immediately on startup to clear old expired items
    cleanup_expired()
    await flush()

    last_cleanup = datetime.now(UTC)

    while True:
        try:
            await asyncio.sleep(FLUSH_INTERVAL)
            # Flush pending changes to disk
            await flush()

            # Run cleanup periodically
            now = datetime.now(UTC)
            if (now - last_cleanup).total_seconds() >= CLEANUP_INTERVAL:
                cleanup_expired()
                await flush()  # Flush cleanup changes
                last_cleanup = now
        except asyncio.CancelledError:
            # Final flush before exit
            await flush()
            break
        except Exception:
            _logger.debug("Error in database background loop", exc_info=True)


async def start_background():
    """Start the background flush/cleanup task."""
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
                if loop is not task_loop:
                    _logger.debug("Background task in different event loop, restarting")
                    _background_task = None
                else:
                    # Task is already running in same loop - idempotent, just return
                    # This happens with dual IPv4+IPv6 endpoints sharing the same process
                    _logger.debug(
                        "Background task already running in same loop, skipping"
                    )
                    return
            except Exception as e:
                _logger.debug("Error checking background task loop: %s, restarting", e)
                _background_task = None

    if _background_task is None:
        _background_task = asyncio.create_task(_background_loop())


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
