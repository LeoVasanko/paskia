"""
Session management for WebAuthn authentication.

This module provides session management functionality including:
- Getting current user from session cookies
- Setting and clearing HTTP-only cookies
- Session validation and token handling
- Device addition token management
- Device addition route handlers
"""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import Request, Response, WebSocket

from ..db import Session, db
from ..util import passphrase
from ..util.tokens import create_token, reset_key, session_key

EXPIRES = timedelta(hours=24)


def expires() -> datetime:
    return datetime.now() + EXPIRES


def infodict(request: Request | WebSocket, type: str) -> dict:
    """Extract client information from request."""
    return {
        "ip": request.client.host if request.client else "",
        "user_agent": request.headers.get("user-agent", "")[:500],
        "type": type,
    }


async def create_session(user_uuid: UUID, info: dict, credential_uuid: UUID) -> str:
    """Create a new session and return a session token."""
    token = create_token()
    await db.instance.create_session(
        user_uuid=user_uuid,
        key=session_key(token),
        expires=datetime.now() + EXPIRES,
        info=info,
        credential_uuid=credential_uuid,
    )
    return token


async def get_session(token: str, reset_allowed=False) -> Session:
    """Validate a session token and return session data if valid."""
    if passphrase.is_well_formed(token):
        if not reset_allowed:
            raise ValueError("Reset link is not allowed for this endpoint")
        key = reset_key(token)
    else:
        key = session_key(token)

    session = await db.instance.get_session(key)
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


def set_session_cookie(response: Response, token: str) -> None:
    """Set the session token as an HTTP-only cookie."""
    response.set_cookie(
        key="auth",
        value=token,
        max_age=int(EXPIRES.total_seconds()),
        httponly=True,
        secure=True,
        path="/auth/",
    )


async def delete_credential(credential_uuid: UUID, auth: str):
    """Delete a specific credential for the current user."""
    s = await get_session(auth)
    await db.instance.delete_credential(credential_uuid, s.user_uuid)
