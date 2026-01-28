"""Utility functions for session validation and checking."""

from datetime import UTC, datetime

from paskia.authsession import EXPIRES
from paskia.db import SessionContext
from paskia.util.timeutil import parse_duration


def check_session_age(ctx: SessionContext, max_age: str | None) -> bool:
    """Check if a session satisfies the max_age requirement.

    Uses the credential's last_used timestamp to determine authentication age,
    since session renewal can happen without re-authentication.

    Args:
        ctx: The session context containing session and credential info
        max_age: Maximum age string (e.g., "5m", "1h", "30s") or None

    Returns:
        True if authentication is recent enough or max_age is None, False if too old

    Raises:
        ValueError: If max_age format is invalid
    """
    if not max_age:
        return True

    max_age_delta = parse_duration(max_age)

    # Use credential's last_used time if available, fall back to session renewed time
    if ctx.credential and ctx.credential.last_used:
        auth_time = ctx.credential.last_used
    else:
        auth_time = ctx.session.expiry - EXPIRES

    time_since_auth = datetime.now(UTC) - auth_time
    return time_since_auth <= max_age_delta
