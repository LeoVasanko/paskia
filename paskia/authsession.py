"""
Core session management for WebAuthn authentication.

This module provides generic session management functionality that is
independent of any web framework:
- Session creation and validation
- Token handling and refresh
- Credential management
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID

from paskia import db
from paskia.config import RESET_LIFETIME, SESSION_LIFETIME
from paskia.util import hostutil

if TYPE_CHECKING:
    from paskia.db import ResetToken

EXPIRES = SESSION_LIFETIME


def expires() -> datetime:
    return datetime.now(timezone.utc) + EXPIRES


def reset_expires() -> datetime:
    return datetime.now(timezone.utc) + RESET_LIFETIME


def get_reset(token: str) -> "ResetToken":
    """Validate a credential reset token."""

    record = db.get_reset_token(token)
    if record:
        return record
    raise ValueError("This authentication link is no longer valid.")


def refresh_session_token(token: str, *, ip: str, user_agent: str):
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


def delete_credential(credential_uuid: UUID, auth: str, host: str | None = None):
    """Delete a specific credential for the current user."""
    ctx = db.data().session_ctx(auth, hostutil.normalize_host(host))
    if not ctx:
        raise ValueError("Session expired")
    db.delete_credential(credential_uuid, ctx.user.uuid)
