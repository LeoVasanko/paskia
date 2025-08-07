"""
Core session management for WebAuthn authentication.

This module provides generic session management functionality that is
independent of any web framework:
- Session creation and validation
- Token handling and refresh
- Credential management
"""

from datetime import datetime, timedelta
from uuid import UUID

from .db import Session
from .globals import db
from .util.tokens import create_token, reset_key, session_key

EXPIRES = timedelta(hours=24)


def expires() -> datetime:
    return datetime.now() + EXPIRES


async def create_session(user_uuid: UUID, credential_uuid: UUID, info: dict) -> str:
    """Create a new session and return a session token."""
    token = create_token()
    await db.instance.create_session(
        user_uuid=user_uuid,
        credential_uuid=credential_uuid,
        key=session_key(token),
        expires=datetime.now() + EXPIRES,
        info=info,
    )
    return token


async def get_reset(token: str) -> Session:
    """Validate a credential reset token. Returns None if the token is not well formed (i.e. it is another type of token)."""
    session = await db.instance.get_session(reset_key(token))
    if not session:
        raise ValueError("Invalid or expired session token")
    return session


async def get_session(token: str) -> Session:
    """Validate a session token and return session data if valid."""
    session = await db.instance.get_session(session_key(token))
    if not session:
        raise ValueError("Invalid or expired session token")
    return session


async def refresh_session_token(token: str):
    """Refresh a session extending its expiry."""
    # Get the current session
    s = await db.instance.update_session(
        session_key(token), datetime.now() + EXPIRES, {}
    )

    if not s:
        raise ValueError("Session not found or expired")


async def delete_credential(credential_uuid: UUID, auth: str):
    """Delete a specific credential for the current user."""
    s = await get_session(auth)
    await db.instance.delete_credential(credential_uuid, s.user_uuid)
