"""
JSONL persistence layer for the database.
"""

from __future__ import annotations

import json
import logging
import sys
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import aiofiles
import jsondiff
import msgspec

from paskia.db.structs import DB, SessionContext

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


# Actions that are allowed to create a new database file
_BOOTSTRAP_ACTIONS = frozenset({"bootstrap", "migrate"})


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

    if not db_path.exists():
        first_action = pending_changes[0].a
        if first_action not in _BOOTSTRAP_ACTIONS:
            _logger.error(
                "Refusing to create database file with action '%s' - "
                "only bootstrap or migrate can create a new database",
                first_action,
            )
            pending_changes.clear()
            return False

    changes_to_write = list(pending_changes)
    pending_changes.clear()

    try:
        lines = [_change_encoder.encode(change) for change in changes_to_write]
        if not lines:
            return True

        async with aiofiles.open(db_path, "ab") as f:
            await f.write(b"\n".join(lines) + b"\n")
        return True
    except OSError:
        _logger.exception("Failed to flush database changes")
        # Re-queue the changes on failure
        for change in reversed(changes_to_write):
            pending_changes.appendleft(change)
        return False


class JsonlStore:
    """JSONL persistence layer for a DB instance."""

    def __init__(self, db: DB, db_path: str = DB_PATH_DEFAULT):
        self.db: DB = db
        self.db_path = Path(db_path)
        self._previous_builtins: dict[str, Any] = {}
        self._pending_changes: deque[_ChangeRecord] = deque()
        self._current_action: str = "system"
        self._current_user: str | None = None
        self._in_transaction: bool = False
        self._transaction_snapshot: dict[str, Any] | None = None

    async def load(self, db_path: str | None = None) -> None:
        """Load data from JSONL change log."""
        if db_path is not None:
            self.db_path = Path(db_path)
        try:
            data_dict = await load_jsonl(self.db_path)
            if data_dict:
                decoder = msgspec.json.Decoder(DB)
                self.db = decoder.decode(msgspec.json.encode(data_dict))
                self.db._store = self
                self._previous_builtins = data_dict
        except ValueError:
            if self.db_path.exists():
                raise

    def _queue_change(self) -> None:
        current = msgspec.to_builtins(self.db)
        diff = compute_diff(self._previous_builtins, current)
        if diff:
            self._pending_changes.append(
                create_change_record(self._current_action, diff, self._current_user)
            )
            self._previous_builtins = current
            # Log the change with user display name if available
            user_display = None
            if self._current_user:
                try:
                    user_uuid = UUID(self._current_user)
                    if user_uuid in self.db.users:
                        user_display = self.db.users[user_uuid].display_name
                except (ValueError, KeyError):
                    user_display = self._current_user

            diff_json = json.dumps(diff, default=str)
            if user_display:
                print(
                    f"{self._current_action} by {user_display}: {diff_json}",
                    file=sys.stderr,
                )
            else:
                print(f"{self._current_action}: {diff_json}", file=sys.stderr)

    @contextmanager
    def transaction(
        self,
        action: str,
        ctx: SessionContext | None = None,
        *,
        user: str | None = None,
    ):
        """Wrap writes in transaction. Queues change on successful exit.

        Args:
            action: Describes the operation (e.g., "Created user", "Login")
            ctx: Session context of user performing the action (None for system operations)
            user: User UUID string (alternative to ctx when full context unavailable)
        """
        if self._in_transaction:
            raise RuntimeError("Nested transactions are not supported")

        # Check for out-of-transaction modifications
        current_state = msgspec.to_builtins(self.db)
        if current_state != self._previous_builtins:
            _logger.error(
                "Database state modified outside of transaction! "
                "This indicates a bug where DB changes occurred without a transaction wrapper. "
                "Resetting to last known state from JSONL file."
            )
            # Hard reset to last known good state
            decoder = msgspec.json.Decoder(DB)
            self.db = decoder.decode(msgspec.json.encode(self._previous_builtins))
            self.db._store = self
            current_state = self._previous_builtins.copy()

        old_action = self._current_action
        old_user = self._current_user
        self._current_action = action
        # Prefer ctx.user.uuid if ctx provided, otherwise use user param
        self._current_user = str(ctx.user.uuid) if ctx else user
        self._in_transaction = True
        self._transaction_snapshot = current_state

        try:
            yield
            self._queue_change()
        except Exception:
            # Rollback on error: restore from snapshot
            _logger.warning("Transaction '%s' failed, rolling back changes", action)
            if self._transaction_snapshot is not None:
                decoder = msgspec.json.Decoder(DB)
                self.db = decoder.decode(
                    msgspec.json.encode(self._transaction_snapshot)
                )
                self.db._store = self
            raise
        finally:
            self._current_action = old_action
            self._current_user = old_user
            self._in_transaction = False
            self._transaction_snapshot = None

    async def flush(self) -> bool:
        """Write all pending changes to disk."""
        return await flush_changes(self.db_path, self._pending_changes)
