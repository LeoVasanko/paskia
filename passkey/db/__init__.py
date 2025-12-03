"""
Database module for WebAuthn passkey authentication.

This module provides dataclasses and database abstractions for managing
users, credentials, and sessions in a WebAuthn authentication system.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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
    # List of permission IDs this role grants to its members
    permissions: list[str] = field(default_factory=list)  # permission IDs


@dataclass
class Org:
    uuid: UUID
    display_name: str
    # All permission IDs that the Org is allowed to grant to its roles
    permissions: list[str] = field(default_factory=list)  # permission IDs
    # Roles belonging to this org
    roles: list[Role] = field(default_factory=list)


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
    credential_uuid: UUID
    host: str
    ip: str
    user_agent: str
    renewed: datetime

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "renewed": self.renewed.isoformat(),
        }


@dataclass
class ResetToken:
    key: bytes
    user_uuid: UUID
    expiry: datetime
    token_type: str


@dataclass
class SessionContext:
    session: Session
    user: User
    org: Org
    role: Role
    credential: Credential | None = None
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

    @abstractmethod
    async def update_user_display_name(
        self, user_uuid: UUID, display_name: str
    ) -> None:
        """Update a user's display name."""

    # Role operations
    @abstractmethod
    async def create_role(self, role: Role) -> None:
        """Create new role."""

    @abstractmethod
    async def update_role(self, role: Role) -> None:
        """Update a role's display name and synchronize its permissions."""

    @abstractmethod
    async def delete_role(self, role_uuid: UUID) -> None:
        """Delete a role by UUID. Implementations may prevent deletion if users exist."""

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
        credential_uuid: UUID,
        host: str,
        ip: str,
        user_agent: str,
        renewed: datetime,
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
        self,
        key: bytes,
        *,
        ip: str,
        user_agent: str,
        renewed: datetime,
    ) -> Session | None:
        """Update session metadata and touch renewed timestamp."""

    @abstractmethod
    async def set_session_host(self, key: bytes, host: str) -> None:
        """Bind a session to a specific host if not already set."""

    @abstractmethod
    async def list_sessions_for_user(self, user_uuid: UUID) -> list[Session]:
        """Return all sessions for a user (including other hosts)."""

    @abstractmethod
    async def cleanup(self) -> None:
        """Called periodically to clean up expired records."""

    @abstractmethod
    async def delete_sessions_for_user(self, user_uuid: UUID) -> None:
        """Delete all sessions belonging to the provided user."""

    # Reset token operations
    @abstractmethod
    async def create_reset_token(
        self,
        user_uuid: UUID,
        key: bytes,
        expiry: datetime,
        token_type: str,
    ) -> None:
        """Create a reset token for a user."""

    @abstractmethod
    async def get_reset_token(self, key: bytes) -> ResetToken | None:
        """Retrieve a reset token by key."""

    @abstractmethod
    async def delete_reset_token(self, key: bytes) -> None:
        """Delete a reset token by key."""

    # Organization operations
    @abstractmethod
    async def create_organization(self, org: Org) -> None:
        """Add a new organization."""

    @abstractmethod
    async def get_organization(self, org_id: str) -> Org:
        """Get organization by ID, including its permission IDs and roles (with their permission IDs)."""

    @abstractmethod
    async def list_organizations(self) -> list[Org]:
        """List all organizations with their roles and permission IDs."""

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
    async def get_roles_by_organization(self, org_id: str) -> list[Role]:
        """List roles belonging to an organization."""

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
    async def list_permissions(self) -> list[Permission]:
        """List all permissions."""

    @abstractmethod
    async def update_permission(self, permission: Permission) -> None:
        """Update permission details."""

    @abstractmethod
    async def delete_permission(self, permission_id: str) -> None:
        """Delete permission by ID."""

    @abstractmethod
    async def rename_permission(
        self, old_id: str, new_id: str, display_name: str
    ) -> None:
        """Rename a permission's ID (and display name) updating all references.

        This must update:
            - permissions.id (primary key)
            - org_permissions.permission_id
            - role_permissions.permission_id
        """

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

    # Role-permission operations
    @abstractmethod
    async def add_permission_to_role(self, role_uuid: UUID, permission_id: str) -> None:
        """Add a permission to a role."""

    @abstractmethod
    async def remove_permission_from_role(
        self, role_uuid: UUID, permission_id: str
    ) -> None:
        """Remove a permission from a role."""

    @abstractmethod
    async def get_role_permissions(self, role_uuid: UUID) -> list[Permission]:
        """List all permissions granted to a role."""

    @abstractmethod
    async def get_permission_roles(self, permission_id: str) -> list[Role]:
        """List all roles that grant a permission."""

    @abstractmethod
    async def get_role(self, role_uuid: UUID) -> Role:
        """Get a role by UUID, including its permission IDs."""

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
    async def get_session_context(
        self, session_key: bytes, host: str | None = None
    ) -> SessionContext | None:
        """Get complete session context including user, organization, role, and permissions."""

    # Combined atomic operations
    @abstractmethod
    async def create_credential_session(
        self,
        user_uuid: UUID,
        credential: Credential,
        reset_key: bytes | None,
        session_key: bytes,
        *,
        display_name: str | None = None,
        host: str | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """Atomically add a credential and create a session.

        Steps (single transaction):
            1. Insert credential
            2. Optionally delete old reset token if provided
            3. Optionally update user's display name
            4. Insert new session referencing the credential
            5. Update user's last_seen and increment visits (treat as a login)
        """


__all__ = [
    "User",
    "Credential",
    "Session",
    "ResetToken",
    "SessionContext",
    "Org",
    "Role",
    "Permission",
    "DatabaseInterface",
]
