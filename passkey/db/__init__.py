"""
Database module for WebAuthn passkey authentication.

This module provides dataclasses and database abstractions for managing
users, credentials, and sessions in a WebAuthn authentication system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass
class User:
    user_uuid: UUID
    user_name: str
    created_at: datetime | None = None
    last_seen: datetime | None = None
    visits: int = 0


@dataclass
class Credential:
    uuid: UUID
    credential_id: bytes  # Long binary ID passed from the authenticator
    user_uuid: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None


@dataclass
class Org:
    """Organization data structure."""

    id: str  # ASCII primary key
    options: dict


@dataclass
class Session:
    """Session data structure."""

    key: bytes
    user_uuid: UUID
    expires: datetime
    info: dict
    credential_uuid: UUID | None = None


class DatabaseInterface(ABC):
    """Abstract base class defining the database interface.

    This class defines the public API that database implementations should provide.
    Implementations may use decorators like @with_session that modify method signatures
    at runtime, so this interface focuses on the logical operations rather than
    exact parameter matching.
    """

    @abstractmethod
    async def init_db(self) -> None:
        """Initialize database tables."""
        pass

    # User operations
    @abstractmethod
    async def get_user_by_user_uuid(self, user_uuid: UUID) -> User:
        """Get user record by WebAuthn user UUID."""

    @abstractmethod
    async def create_user(self, user: User) -> None:
        """Create a new user."""

    # Credential operations
    @abstractmethod
    async def create_credential(self, credential: Credential) -> None:
        """Store a credential for a user."""

    @abstractmethod
    async def get_credential_by_id(self, credential_id: bytes) -> Credential:
        """Get credential by credential ID."""

    @abstractmethod
    async def get_credentials_by_user_uuid(self, user_uuid: UUID) -> list[bytes]:
        """Get all credential IDs for a user."""

    @abstractmethod
    async def update_credential(self, credential: Credential) -> None:
        """Update the sign count, created_at, last_used, and last_verified for a credential."""

    @abstractmethod
    async def delete_credential(self, uuid: UUID, user_uuid: UUID) -> None:
        """Delete a specific credential for a user."""

    # Session operations
    @abstractmethod
    async def create_session(
        self,
        user_uuid: UUID,
        key: bytes,
        expires: datetime,
        info: dict,
        credential_uuid: UUID | None = None,
    ) -> None:
        """Create a new session."""

    @abstractmethod
    async def get_session(self, key: bytes) -> Session | None:
        """Get session by key."""

    @abstractmethod
    async def delete_session(self, key: bytes) -> None:
        """Delete session by key."""

    @abstractmethod
    async def update_session(
        self, key: bytes, expires: datetime, info: dict
    ) -> Session | None:
        """Update session expiry and info."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Called periodically to clean up expired records."""

    # Organization operations
    @abstractmethod
    async def create_organization(self, organization: Org) -> None:
        """Create a new organization."""

    @abstractmethod
    async def get_organization(self, org_id: str) -> Org:
        """Get organization by ID."""

    @abstractmethod
    async def update_organization(self, organization: Org) -> None:
        """Update organization options."""

    @abstractmethod
    async def delete_organization(self, org_id: str) -> None:
        """Delete organization by ID."""

    @abstractmethod
    async def add_user_to_organization(
        self, user_uuid: UUID, org_id: str, role: str
    ) -> None:
        """Add a user to an organization with a specific role."""

    @abstractmethod
    async def remove_user_from_organization(self, user_uuid: UUID, org_id: str) -> None:
        """Remove a user from an organization."""

    @abstractmethod
    async def get_user_org_role(self, user_uuid: UUID) -> list[tuple[Org, str]]:
        """Get all organizations for a user with their roles."""

    @abstractmethod
    async def get_organization_users(self, org_id: str) -> list[tuple[User, str]]:
        """Get all users in an organization with their roles."""

    # Combined operations
    @abstractmethod
    async def login(self, user_uuid: UUID, credential: Credential) -> None:
        """Update user and credential timestamps after successful login."""

    @abstractmethod
    async def create_user_and_credential(
        self, user: User, credential: Credential
    ) -> None:
        """Create a new user and their first credential in a transaction."""


class DatabaseManager:
    """Manager for the global database instance."""

    def __init__(self):
        self._instance: DatabaseInterface | None = None

    @property
    def instance(self) -> DatabaseInterface:
        if self._instance is None:
            raise RuntimeError(
                "Database not initialized. Call e.g. db.sql.init() first."
            )
        return self._instance

    @instance.setter
    def instance(self, instance: DatabaseInterface) -> None:
        self._instance = instance


db = DatabaseManager()


__all__ = [
    "User",
    "Credential",
    "Session",
    "Org",
    "DatabaseInterface",
    "db",
]
