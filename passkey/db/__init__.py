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
class Permission:
    id: str  # String primary key (max 128 chars)
    display_name: str


@dataclass
class Role:
    uuid: UUID
    org_uuid: UUID
    display_name: str
    permissions: list[Permission]


@dataclass
class Org:
    uuid: UUID
    display_name: str
    permissions: list[Permission]  # All that the Org can grant
    roles: list[Role]


@dataclass
class User:
    uuid: UUID
    display_name: str
    role_uuid: UUID
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
class Session:
    key: bytes
    user_uuid: UUID
    expires: datetime
    info: dict
    credential_uuid: UUID | None = None


@dataclass
class SessionContext:
    session: Session
    user: User
    org: Org
    role: Role
    permissions: list[Permission] | None = None


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
    async def get_user_by_uuid(self, user_uuid: UUID) -> User:
        """Get user record by WebAuthn user UUID."""

    @abstractmethod
    async def create_user(self, user: User) -> None:
        """Create a new user."""

    # Role operations
    @abstractmethod
    async def create_role(self, role: Role) -> None:
        """Create new role."""

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
    async def create_organization(self, org: Org) -> None:
        """Add a new organization."""

    @abstractmethod
    async def get_organization(self, org_id: str) -> Org:
        """Get organization by ID."""

    @abstractmethod
    async def update_organization(self, org: Org) -> None:
        """Update organization options."""

    @abstractmethod
    async def delete_organization(self, org_uuid: UUID) -> None:
        """Delete organization by ID."""

    @abstractmethod
    async def add_user_to_organization(
        self, user_uuid: UUID, org_id: str, role: str
    ) -> None:
        """Set a user's organization and role."""

    @abstractmethod
    async def transfer_user_to_organization(
        self, user_uuid: UUID, new_org_id: str, new_role: str | None = None
    ) -> None:
        """Transfer a user to another organization with an optional role."""

    @abstractmethod
    async def get_user_organization(self, user_uuid: UUID) -> tuple[Org, str]:
        """Get the organization and role for a user."""

    @abstractmethod
    async def get_organization_users(self, org_id: str) -> list[tuple[User, str]]:
        """Get all users in an organization with their roles."""

    @abstractmethod
    async def get_user_role_in_organization(
        self, user_uuid: UUID, org_id: str
    ) -> str | None:
        """Get a user's role in a specific organization."""

    @abstractmethod
    async def update_user_role_in_organization(
        self, user_uuid: UUID, new_role: str
    ) -> None:
        """Update a user's role in their organization."""

    # Permission operations
    @abstractmethod
    async def create_permission(self, permission: Permission) -> None:
        """Create a new permission."""

    @abstractmethod
    async def get_permission(self, permission_id: str) -> Permission:
        """Get permission by ID."""

    @abstractmethod
    async def update_permission(self, permission: Permission) -> None:
        """Update permission details."""

    @abstractmethod
    async def delete_permission(self, permission_id: str) -> None:
        """Delete permission by ID."""

    @abstractmethod
    async def add_permission_to_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        """Add a permission to an organization."""

    @abstractmethod
    async def remove_permission_from_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        """Remove a permission from an organization."""

    @abstractmethod
    async def get_organization_permissions(self, org_id: str) -> list[Permission]:
        """Get all permissions assigned to an organization."""

    @abstractmethod
    async def get_permission_organizations(self, permission_id: str) -> list[Org]:
        """Get all organizations that have a specific permission."""

    # Combined operations
    @abstractmethod
    async def login(self, user_uuid: UUID, credential: Credential) -> None:
        """Update user and credential timestamps after successful login."""

    @abstractmethod
    async def create_user_and_credential(
        self, user: User, credential: Credential
    ) -> None:
        """Create a new user and their first credential in a transaction."""

    @abstractmethod
    async def get_session_context(self, session_key: bytes) -> SessionContext | None:
        """Get complete session context including user, organization, role, and permissions."""


__all__ = [
    "User",
    "Credential",
    "Session",
    "SessionContext",
    "Org",
    "Permission",
    "DatabaseInterface",
]
