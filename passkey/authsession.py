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

from .config import SESSION_LIFETIME
from .db import ResetToken, Session
from .globals import db
from .util import hostutil
from .util.tokens import create_token, reset_key, session_key

EXPIRES = SESSION_LIFETIME


def expires() -> datetime:
    return datetime.now(timezone.utc) + EXPIRES


def reset_expires() -> datetime:
    from .config import RESET_LIFETIME

    return datetime.now(timezone.utc) + RESET_LIFETIME


def session_expiry(session: Session) -> datetime:
    """Calculate the expiration timestamp for a session (UTC aware)."""
    # After migration all renewed timestamps are timezone-aware UTC
    return session.renewed + EXPIRES


async def create_session(
    user_uuid: UUID,
    credential_uuid: UUID,
    *,
    host: str,
    ip: str,
    user_agent: str,
) -> str:
    """Create a new session and return a session token."""
    normalized_host = hostutil.normalize_host(host)
    if not normalized_host:
        raise ValueError("Host required for session creation")
    token = create_token()
    now = datetime.now(timezone.utc)
    await db.instance.create_session(
        user_uuid=user_uuid,
        credential_uuid=credential_uuid,
        key=session_key(token),
        host=normalized_host,
        ip=ip,
        user_agent=user_agent,
        renewed=now,
    )
    return token


async def get_reset(token: str) -> ResetToken:
    """Validate a credential reset token. Returns None if the token is not well formed (i.e. it is another type of token)."""
    record = await db.instance.get_reset_token(reset_key(token))
    if not record:
        raise ValueError("Invalid or expired session token")
    if record.expiry < datetime.now(timezone.utc):
        await db.instance.delete_reset_token(record.key)
        raise ValueError("Invalid or expired session token")
    return record


async def get_session(token: str, host: str | None = None) -> Session:
    """Validate a session token and return session data if valid."""
    session = await db.instance.get_session(session_key(token))
    if not session:
        raise ValueError("Invalid or expired session token")
    if session_expiry(session) < datetime.now(timezone.utc):
        await db.instance.delete_session(session.key)
        raise ValueError("Invalid or expired session token")
    if host is not None:
        normalized_host = hostutil.normalize_host(host)
        if not normalized_host:
            raise ValueError("Invalid host")
        current = session.host
        if current is None:
            # First time binding: store exact host:port (or IPv6 form) now.
            await db.instance.set_session_host(session.key, normalized_host)
            session.host = normalized_host
        elif current == normalized_host:
            pass  # exact match ok
        else:
            raise ValueError("Invalid or expired session token")
    return session


async def refresh_session_token(token: str, *, ip: str, user_agent: str):
    """Refresh a session extending its expiry."""
    session_record = await db.instance.get_session(session_key(token))
    if not session_record:
        raise ValueError("Session not found or expired")
    updated = await db.instance.update_session(
        session_key(token),
        ip=ip,
        user_agent=user_agent,
        renewed=datetime.now(timezone.utc),
    )
    if not updated:
        raise ValueError("Session not found or expired")


async def delete_credential(credential_uuid: UUID, auth: str, host: str | None = None):
    """Delete a specific credential for the current user."""
    s = await get_session(auth, host=host)
    await db.instance.delete_credential(credential_uuid, s.user_uuid)
