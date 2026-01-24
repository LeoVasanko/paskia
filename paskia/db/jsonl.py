"""
JSONL persistence layer for the database.

Handles file I/O, JSON diffs, and persistence. Works with plain JSON/dict data.
Uses aiofiles for async I/O operations.
"""

import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

import aiofiles
import jsondiff
import msgspec

_logger = logging.getLogger(__name__)

# Default database path
DB_PATH_DEFAULT = "paskia.jsonl"


class _ChangeRecord(msgspec.Struct, omit_defaults=True):
    """A single change record in the JSONL file."""

    ts: datetime
    a: str  # action - describes the operation (e.g., "migrate", "login", "create_user")
    u: str | None = None  # user UUID who performed the action (None for system)
    diff: dict = {}


# msgspec encoder for change records
_change_encoder = msgspec.json.Encoder()


async def load_jsonl(db_path: Path) -> dict:
    """Load data from disk by applying change log.

    Replays all changes from JSONL file using plain dicts (to handle
    schema evolution).

    Args:
        db_path: Path to the JSONL database file

    Returns:
        The final state after applying all changes

    Raises:
        ValueError: If file doesn't exist or cannot be loaded
    """
    if not db_path.exists():
        raise ValueError(f"Database file not found: {db_path}")
    data_dict: dict = {}
    try:
        # Read entire file at once and split into lines
        async with aiofiles.open(db_path, "rb") as f:
            content = await f.read()
        for line_num, line in enumerate(content.split(b"\n"), 1):
            line = line.strip()
            if not line:
                continue
            try:
                change = msgspec.json.decode(line)
                # Apply the diff to current state (marshal=True for $-prefixed keys)
                data_dict = jsondiff.patch(data_dict, change["diff"], marshal=True)
            except Exception as e:
                raise ValueError(f"Error parsing line {line_num}: {e}")
    except (OSError, ValueError, msgspec.DecodeError) as e:
        raise ValueError(f"Failed to load database: {e}")
    return data_dict


def compute_diff(previous: dict, current: dict) -> dict | None:
    """Compute JSON diff between two states.

    Args:
        previous: Previous state (JSON-compatible dict)
        current: Current state (JSON-compatible dict)

    Returns:
        The diff, or None if no changes
    """
    diff = jsondiff.diff(previous, current, marshal=True)
    return diff if diff else None


def create_change_record(
    action: str, diff: dict, user: str | None = None
) -> _ChangeRecord:
    """Create a change record for persistence."""
    return _ChangeRecord(
        ts=datetime.now(timezone.utc),
        a=action,
        u=user,
        diff=diff,
    )


async def flush_changes(
    db_path: Path,
    pending_changes: deque[_ChangeRecord],
) -> bool:
    """Write all pending changes to disk.

    Args:
        db_path: Path to the JSONL database file
        pending_changes: Queue of pending change records (will be cleared on success)

    Returns:
        True if flush succeeded, False otherwise
    """
    if not pending_changes:
        return True

    # Collect all pending changes
    changes_to_write = list(pending_changes)
    pending_changes.clear()

    try:
        # Build lines to append (keep as bytes, join with \n)
        lines = [_change_encoder.encode(change) for change in changes_to_write]

        # Append all lines in a single write (binary mode for Windows compatibility)
        async with aiofiles.open(db_path, "ab") as f:
            await f.write(b"\n".join(lines) + b"\n")
        return True
    except OSError:
        _logger.exception("Failed to flush database changes")
        # Re-queue the changes on failure
        for change in reversed(changes_to_write):
            pending_changes.appendleft(change)
        return False
