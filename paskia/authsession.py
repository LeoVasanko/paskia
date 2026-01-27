"""
Core session management for WebAuthn authentication.

This module provides generic session management functionality that is
independent of any web framework:
- Session creation and validation
- Token handling and refresh
- Credential management
"""

from datetime import datetime, timezone
from uuid import UUID

from paskia import db
from paskia.config import SESSION_LIFETIME
from paskia.db import ResetToken, Session
from paskia.util import hostutil

EXPIRES = SESSION_LIFETIME


def expires() -> datetime:
    return datetime.now(timezone.utc) + EXPIRES


def reset_expires() -> datetime:
    from .config import RESET_LIFETIME

    return datetime.now(timezone.utc) + RESET_LIFETIME


async def get_reset(token: str) -> ResetToken:
    """Validate a credential reset token."""
    record = db.get_reset_token(token)
    if record:
        return record
    raise ValueError("This authentication link is no longer valid.")


async def get_session(token: str, host: str | None = None) -> Session:
    """Validate a session token and return session data if valid."""
    host = hostutil.normalize_host(host)
    if not host:
        raise ValueError("Invalid host")
    session = db.data().sessions.get(token)
    if session:
        if session.host is None:
            # First time binding: store exact host:port (or IPv6 form) now.
            db.set_session_host(session.key, host)
            session.host = host
        elif session.host != host:
            raise ValueError("Session host mismatch")
        return session
    raise ValueError("Your session has expired. Please sign in again!")


async def refresh_session_token(token: str, *, ip: str, user_agent: str):
    """Refresh a session extending its expiry."""
    session_record = db.data().sessions.get(token)
    if not session_record:
        raise ValueError("Session not found or expired")
    updated = db.update_session(
        token,
        ip=ip,
        user_agent=user_agent,
        expiry=expires(),
    )
    if not updated:
        raise ValueError("Session not found or expired")


async def delete_credential(credential_uuid: UUID, auth: str, host: str | None = None):
    """Delete a specific credential for the current user."""
    s = await get_session(auth, host=host)
    db.delete_credential(credential_uuid, s.user)
