"""
Database module for WebAuthn passkey authentication.

This module provides dataclasses and database abstractions for managing
users, credentials, and sessions in a WebAuthn authentication system.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass
class User:
    """User data structure."""

    user_uuid: UUID
    user_name: str
    created_at: datetime | None = None
    last_seen: datetime | None = None
    visits: int = 0


@dataclass
class Credential:
    """Credential data structure."""

    uuid: UUID
    credential_id: bytes
    user_uuid: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None


@dataclass
class Session:
    """Session data structure."""

    key: bytes
    user_uuid: UUID
    expires: datetime
    credential_uuid: UUID | None = None
    info: dict | None = None


__all__ = ["User", "Credential", "Session"]
