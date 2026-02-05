"""
JSONL persistence layer for the database.
"""

import copy
import logging
from collections import deque
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import aiofiles
import jsondiff
import msgspec

from paskia.db.logging import log_change
from paskia.db.migrations import DBVER, apply_all_migrations
from paskia.db.structs import DB, SessionContext

_logger = logging.getLogger(__name__)

# Default database path
DB_PATH_DEFAULT = "paskia.jsonl"


class _ChangeRecord(msgspec.Struct, omit_defaults=True):
    """A single change record in the JSONL file."""

    ts: datetime
    a: str  # action - describes the operation (e.g., "migrate", "login", "create_user")
    v: int  # schema version after this change
    u: str | None = None  # user UUID who performed the action (None for system)
    diff: dict = {}


# msgspec encoder for change records
_change_encoder = msgspec.json.Encoder()


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
    action: str, version: int, diff: dict, user: str | None = None
) -> _ChangeRecord:
    """Create a change record for persistence."""
    return _ChangeRecord(
        ts=datetime.now(UTC),
        a=action,
        v=version,
        u=user,
        diff=diff,
    )


# Actions that are allowed to create a new database file
_BOOTSTRAP_ACTIONS = frozenset({"bootstrap"})


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
                "only bootstrap can create a new database",
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
        self._current_version: int = DBVER  # Schema version for new databases

    async def load(self, db_path: str | None = None) -> None:
        """Load data from JSONL change log."""
        if db_path is not None:
            self.db_path = Path(db_path)
        if not self.db_path.exists():
            return

        # Replay change log to reconstruct state
        data_dict: dict = {}
        try:
            async with aiofiles.open(self.db_path, "rb") as f:
                content = await f.read()
            for line_num, line in enumerate(content.split(b"\n"), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    change = msgspec.json.decode(line)
                    data_dict = jsondiff.patch(data_dict, change["diff"], marshal=True)
                    self._current_version = change.get("v", 0)
                except Exception as e:
                    raise ValueError(f"Error parsing line {line_num}: {e}")
        except (OSError, ValueError, msgspec.DecodeError) as e:
            raise ValueError(f"Failed to load database: {e}")

        if not data_dict:
            return

        # Set previous state for diffing (will be updated by _queue_change)
        self._previous_builtins = copy.deepcopy(data_dict)

        # Callback to persist each migration
        async def persist_migration(
            action: str, new_version: int, current: dict
        ) -> None:
            self._current_version = new_version
            self._queue_change(action, new_version, current)

        # Apply schema migrations one at a time
        await apply_all_migrations(data_dict, self._current_version, persist_migration)

        # Decode to msgspec struct
        decoder = msgspec.json.Decoder(DB)
        self.db = decoder.decode(msgspec.json.encode(data_dict))
        self.db._store = self

        # Normalize via msgspec round-trip (handles omit_defaults etc.)
        # This ensures _previous_builtins matches what msgspec would produce
        normalized_dict = msgspec.to_builtins(self.db)
        await persist_migration(
            "migrate:msgspec", self._current_version, normalized_dict
        )

    def _queue_change(
        self, action: str, version: int, current: dict, user: str | None = None
    ) -> None:
        """Queue a change record and log it.

        Args:
            action: The action name for the change record
            version: The schema version for the change record
            current: The current state as a plain dict
            user: Optional user UUID who performed the action
        """
        diff = compute_diff(self._previous_builtins, current)
        if not diff:
            return
        self._pending_changes.append(create_change_record(action, version, diff, user))

        # Log the change with user display name if available
        user_display = None
        if user:
            try:
                user_uuid = UUID(user)
                if user_uuid in self.db.users:
                    user_display = self.db.users[user_uuid].display_name
            except (ValueError, KeyError):
                user_display = user

        log_change(action, diff, user_display, self._previous_builtins)
        self._previous_builtins = copy.deepcopy(current)

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
            # Allow bootstrap to create a new database from empty state
            is_bootstrap = action in _BOOTSTRAP_ACTIONS
            if is_bootstrap and not self._previous_builtins:
                pass  # Expected: creating database from scratch
            else:
                diff = compute_diff(self._previous_builtins, current_state)
                diff_json = msgspec.json.encode(diff).decode()
                _logger.critical(
                    "Database state modified outside of transaction! "
                    "This indicates a bug where DB changes occurred without a transaction wrapper.\n"
                    f"Changes detected:\n{diff_json}"
                )
                raise SystemExit(1)

        old_action = self._current_action
        old_user = self._current_user
        self._current_action = action
        # Prefer ctx.user.uuid if ctx provided, otherwise use user param
        self._current_user = str(ctx.user.uuid) if ctx else user
        self._in_transaction = True
        self._transaction_snapshot = current_state

        try:
            yield
            current = msgspec.to_builtins(self.db)
            self._queue_change(
                self._current_action, self._current_version, current, self._current_user
            )
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
