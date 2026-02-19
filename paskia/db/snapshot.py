"""
Snapshot handling for JSONL database persistence.
"""

import logging
from datetime import UTC, datetime
from typing import Any

import msgspec

_logger = logging.getLogger(__name__)

LINEPREFIX = b"SNAPSHOT "
MINDIFFS = 100


class Snapshot(msgspec.Struct):
    """Snapshot data structure for database persistence."""

    ts: datetime
    v: int
    state: dict[str, Any]


class SnapshotState:
    """Tracks snapshot timing and line counts for a database file."""

    def __init__(self) -> None:
        self.ts: datetime | None = None
        self.changes: int = 0
        self._force_pending: bool = False

    def request_force(self) -> None:
        """Request a forced snapshot on the next maybe_write call."""
        self._force_pending = True

    def record_lines(self, count: int) -> None:
        self.changes += count

    def maybe_write(self, file, version: int, state: dict) -> None:
        """Write a snapshot if conditions are met (enough changes, and Sunday UTC or forced)."""
        if self.changes < MINDIFFS:
            return
        force = self._force_pending
        now = datetime.now(UTC)
        if not force and now.weekday() != 6:  # 6 = Sunday
            return
        sunday_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        if not force and self.ts is not None and self.ts >= sunday_midnight:
            return
        if not file.is_open:
            return
        try:
            self._write(file, version, state, now)
            self._force_pending = False
        except Exception as exc:
            _logger.error("snapshot: failed to write snapshot: %r", exc)

    def _write(self, file, version: int, state: dict, now: datetime) -> None:
        """Write a snapshot and update internal state."""
        data = msgspec.json.encode(Snapshot(ts=now, v=version, state=state))
        file.write(LINEPREFIX + data + b"\n")
        self.changes = 0
        self.ts = now

    @staticmethod
    def load(data: bytes) -> tuple[Snapshot | None, int]:
        """Find and parse the last snapshot in file data.

        Returns (snapshot, replay_offset) where replay_offset is the byte
        position to start replaying change records from. If no valid snapshot
        is found, returns (None, 0).
        """
        marker = b"\n" + LINEPREFIX
        pos = data.rfind(marker)
        if pos != -1:
            pos += 1  # skip the newline
        elif data.startswith(LINEPREFIX):
            pos = 0
        else:
            return None, 0

        end = data.find(b"\n", pos)
        if end == -1:
            raise ValueError("Incomplete snapshot line at end of file")

        snap = msgspec.json.decode(data[pos + len(LINEPREFIX) : end], type=Snapshot)
        return snap, end + 1
