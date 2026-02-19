"""
JSONL persistence layer for the database.
"""

import asyncio
import copy
import logging
import os
import signal
from collections import deque
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import jsondiff
import msgspec

from paskia.db.filelock import LockedFile
from paskia.db.logging import log_change
from paskia.db.migrations import (
    DBVER,
    MigrationCtx,
    apply_all_migrations,
    apply_migrations_readonly,
)
from paskia.db.snapshot import SnapshotState
from paskia.db.structs import DB, Config, SessionContext

_logger = logging.getLogger(__name__)


class ReplayResult(msgspec.Struct, frozen=False):
    """Return value of _replay_from_data"""

    state: dict = {}
    v: int = 0
    ts: datetime | None = None
    snapts: datetime | None = None
    changes: int = 0


class DatabaseError(Exception):
    """Exception raised for database loading errors."""

    pass


def _replay_from_data(data: bytes, db_path: str) -> ReplayResult:
    """Replay database state from file data, using the last snapshot if available."""
    resolved_path = str(Path(db_path).resolve())
    result = ReplayResult()

    # Find and apply the last snapshot
    snap, start_offset = SnapshotState.load(data)
    if snap:
        result.state = snap.state
        result.v = snap.v
        result.snapts = snap.ts

    # Replay change records after the snapshot
    lines = data[start_offset:].split(b"\n")
    for line_num, raw in enumerate(lines, start=1):  # 1-based line numbering
        line = raw.strip()
        if not line:
            continue
        try:
            change = msgspec.json.decode(line, type=ChangeRecord)
        except msgspec.DecodeError as e:
            raise DatabaseError(f"{resolved_path}:{line_num}: {e}")
        result.state = jsondiff.patch(result.state, change.diff, marshal=True)
        result.v = change.v
        result.ts = change.ts
        result.changes += 1

    return result


def load_readonly(db_path: str, *, rp_id: str = "localhost") -> DB:
    """Replay JSONL and apply migrations to produce a DB, without writing anything.

    This is suitable for reading settings before the server starts.
    Migrations are applied in-memory only; nothing is queued or flushed.
    """
    path = Path(db_path)
    if not path.exists():
        return DB(config=Config(rp_id=rp_id))

    try:
        with open(path, "rb") as f:
            content = f.read()
        r = _replay_from_data(content, str(path.resolve()))
        data_dict = r.state
        version = r.v
    except OSError as e:
        _logger.exception("Failed to load database")
        raise SystemExit(f"{e}")
    except (ValueError, msgspec.DecodeError, DatabaseError) as e:
        raise SystemExit(f"{e}")
    except Exception as e:
        _logger.exception("Unexpected error loading database")
        raise SystemExit(f"{e}")

    if not data_dict:
        return DB(config=Config(rp_id=rp_id))

    # Apply migrations in-memory (no persistence)
    apply_migrations_readonly(data_dict, version, MigrationCtx(rp_id=rp_id))

    # Decode to msgspec struct
    db = msgspec.json.decode(msgspec.json.encode(data_dict), type=DB)
    return db


class ChangeRecord(msgspec.Struct, omit_defaults=True, kw_only=True):
    ts: datetime = msgspec.field(default_factory=lambda: datetime.now(UTC))
    a: str = ""  # action (e.g., "migrate", "login", "create_user")
    v: int = 0  # schema version after this change
    u: str | None = None  # user UUID who performed the action (None for system)
    diff: dict


def compute_diff(previous: dict, current: dict) -> dict | None:
    return jsondiff.diff(previous, current, marshal=True) or None


# Actions that are allowed to create a new database file
_BOOTSTRAP_ACTIONS = frozenset({"bootstrap"})


class JsonlStore:
    """JSONL persistence layer for a DB instance."""

    def __init__(self, db: DB, db_path: str):
        self.db: DB = db
        self.db_path = Path(db_path)
        self._file = LockedFile()
        self._flush_failed = False
        self._statedict: dict[str, Any] = {}
        self._pending_changes: deque[ChangeRecord] = deque()
        self._current_action: str = "system"
        self._current_user: str | None = None
        self._in_transaction: bool = False
        self._transaction_snapshot: dict[str, Any] | None = None
        self._v: int = DBVER  # Schema version for new databases
        self._snapshot = SnapshotState()

    async def load(
        self, db_path: str | None = None, *, rp_id: str = "localhost"
    ) -> None:
        """Load data from JSONL change log."""
        if db_path is not None:
            self.db_path = Path(db_path)
        self._rp_id = rp_id
        if not self.db_path.exists():
            return

        # Open with exclusive write lock and read contents — single threadpool call
        content = await asyncio.to_thread(self._file.open_and_read, self.db_path)

        # Replay change log to reconstruct state (snapshot-accelerated)
        try:
            r = _replay_from_data(content, str(self.db_path.resolve()))
            statedict = r.state
            self._v = r.v
            self._snapshot.ts = r.snapts
            self._snapshot.changes = r.changes
        except (OSError, ValueError, msgspec.DecodeError, DatabaseError) as e:
            raise SystemExit(f"{e}")
        except Exception as e:
            _logger.exception("Unexpected error loading database")
            raise SystemExit(f"{e}")

        if not statedict:
            return

        # Set previous state for diffing (will be updated by _queue_change)
        self._statedict = copy.deepcopy(statedict)

        # Callback to persist each migration
        async def persist_migration(
            action: str, new_version: int, current: dict
        ) -> None:
            self._v = new_version
            self._queue_change(action, new_version, current)

        # Apply schema migrations one at a time
        await apply_all_migrations(
            statedict,
            self._v,
            persist_migration,
            MigrationCtx(rp_id=rp_id),
        )

        # Decode to msgspec struct
        decoder = msgspec.json.Decoder(DB)
        self.db = decoder.decode(msgspec.json.encode(statedict))
        self.db._store = self

        # Normalize via msgspec round-trip (handles omit_defaults etc.)
        # This ensures _previous_builtins matches what msgspec would produce
        normalized_dict = msgspec.to_builtins(self.db)
        await persist_migration("migrate:msgspec", self._v, normalized_dict)

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
        diff = compute_diff(self._statedict, current)
        if not diff:
            return
        self._pending_changes.append(
            ChangeRecord(
                a=action,
                v=version,
                u=user,
                diff=diff,
            )
        )

        # Log the change with user display name if available
        user_display = None
        if user:
            try:
                user_uuid = UUID(user)
                if user_uuid in self.db.users:
                    user_display = self.db.users[user_uuid].display_name
            except (ValueError, KeyError):
                user_display = user

        log_change(action, diff, user_display, self._statedict, self.db)
        self._statedict = copy.deepcopy(current)

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
        if current_state != self._statedict:
            # Allow bootstrap to create a new database from empty state
            is_bootstrap = action in _BOOTSTRAP_ACTIONS
            if is_bootstrap and not self._statedict:
                pass  # Expected: creating database from scratch
            else:
                diff = compute_diff(self._statedict, current_state)
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
                self._current_action, self._v, current, self._current_user
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

    async def flush(self) -> None:
        """Write all pending changes to disk.

        On failure, logs an error and sends SIGTERM to trigger graceful shutdown.
        """
        if self._flush_failed or not self._pending_changes:
            return

        if not self._file.is_open:
            first_action = self._pending_changes[0].a
            if first_action not in _BOOTSTRAP_ACTIONS:
                _logger.error(
                    "Refusing to create database file with action '%s' - "
                    "only bootstrap can create a new database",
                    first_action,
                )
                self._flush_failed = True
                os.kill(os.getpid(), signal.SIGTERM)
                return
            # Bootstrap: create and open the file with lock
            await asyncio.to_thread(self._file.open, self.db_path, create=True)

        changes_to_write = list(self._pending_changes)

        try:
            lines = [msgspec.json.encode(change) for change in changes_to_write]
            if not lines:
                self._pending_changes.clear()
                return

            await asyncio.to_thread(self._file.write, b"\n".join(lines) + b"\n")
            self._snapshot.record_lines(len(lines))
            self._pending_changes.clear()
        except OSError as e:
            _logger.error("Failed to flush database: %s", e)
            self._flush_failed = True
            os.kill(os.getpid(), signal.SIGTERM)

    def maybe_snapshot(self) -> None:
        """Write a snapshot if conditions are met."""
        self._snapshot.maybe_write(self._file, self._v, self._statedict)

    def close(self) -> None:
        """Release the file lock and close the file."""
        self._file.close()
