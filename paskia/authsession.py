"""
Core session management for WebAuthn authentication.

This module provides generic session management functionality that is
independent of any web framework:
- Session creation and validation
- Token handling and refresh
- Credential management
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from paskia import db
from paskia.config import RESET_LIFETIME, SESSION_LIFETIME
from paskia.db.structs import ResetToken
from paskia.util import hostutil

if TYPE_CHECKING:
    from paskia.db import ResetToken

EXPIRES = SESSION_LIFETIME


def session_ctx(auth: str, host: str | None = None):
    """Get session context with normalized host."""
    return db.data().session_ctx(auth, hostutil.normalize_host(host))


def expires() -> datetime:
    return datetime.now(UTC) + EXPIRES


def reset_expires() -> datetime:
    return datetime.now(UTC) + RESET_LIFETIME


def get_reset(token: str) -> "ResetToken":
    """Validate a credential reset token."""

    record = ResetToken.by_passphrase(token)
    if record:
        return record
    raise ValueError("This authentication link is no longer valid.")


def delete_credential(credential_uuid: UUID, auth: str, host: str | None = None):
    """Delete a specific credential for the current user."""
    ctx = session_ctx(auth, host)
    if not ctx:
        raise ValueError("Session expired")
    db.delete_credential(credential_uuid, ctx.user.uuid)
