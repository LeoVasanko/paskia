"""Utility functions for session validation and checking."""

from datetime import datetime, timezone

from ..db import Session
from .timeutil import parse_duration


def check_session_age(session: Session, max_age: str | None) -> bool:
    """Check if a session satisfies the max_age requirement.

    Args:
        session: The session record to check
        max_age: Maximum age string (e.g., "5m", "1h", "30s") or None

    Returns:
        True if session is recent enough or max_age is None, False if too old

    Raises:
        ValueError: If max_age format is invalid
    """
    if not max_age:
        return True

    max_age_delta = parse_duration(max_age)
    time_since_auth = datetime.now(timezone.utc) - session.renewed
    return time_since_auth <= max_age_delta
