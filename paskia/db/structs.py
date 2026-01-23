from datetime import datetime
from uuid import UUID

import msgspec


class Permission(msgspec.Struct, omit_defaults=True):
    """A permission that can be granted to roles."""

    uuid: UUID  # UUID primary key
    scope: str  # Permission scope identifier (e.g. "auth:admin", "myapp:write")
    display_name: str
    domain: str | None = None  # If set, scopes permission to this domain


class Role(msgspec.Struct):
    """A role within an organization that can be assigned to users."""

    uuid: UUID
    org_uuid: UUID
    display_name: str
    permissions: list[str] = []  # permission IDs this role grants


class Org(msgspec.Struct):
    """An organization that contains users and roles."""

    uuid: UUID
    display_name: str
    permissions: list[str] = []  # permission IDs this org can grant
    roles: list[Role] = []  # roles belonging to this org


class User(msgspec.Struct):
    """A user in the authentication system."""

    uuid: UUID
    display_name: str
    role_uuid: UUID
    created_at: datetime | None = None
    last_seen: datetime | None = None
    visits: int = 0


class Credential(msgspec.Struct):
    """A WebAuthn credential (passkey) belonging to a user."""

    uuid: UUID
    credential_id: bytes  # Long binary ID from the authenticator
    user_uuid: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None


class Session(msgspec.Struct):
    """An active user session."""

    key: bytes
    user_uuid: UUID
    credential_uuid: UUID
    host: str | None
    ip: str | None
    user_agent: str | None
    expiry: datetime

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expiry": self.expiry.isoformat(),
        }


# -------------------------------------------------------------------------
# Public data types (msgspec Structs)
# -------------------------------------------------------------------------


class ResetToken(msgspec.Struct):
    """A token for password reset or device addition."""

    key: bytes
    user_uuid: UUID
    expiry: datetime
    token_type: str


class SessionContext(msgspec.Struct):
    """Complete context for an authenticated session."""

    session: Session
    user: User
    org: Org
    role: Role
    credential: Credential | None = None
    permissions: list[Permission] | None = None


# -------------------------------------------------------------------------
# Internal storage types (different structure for efficient storage)
# -------------------------------------------------------------------------


class _PermissionData(msgspec.Struct, omit_defaults=True):
    scope: str  # Permission scope identifier
    display_name: str
    domain: str | None = None
    orgs: dict[str, bool] = {}  # org_uuid -> True (which orgs can grant this)


class _OrgData(msgspec.Struct):
    display_name: str
    created_at: datetime | None = None


class _RoleData(msgspec.Struct):
    org: str
    display_name: str
    permissions: dict[str, bool]  # permission_id -> True


class _UserData(msgspec.Struct):
    display_name: str
    role: str
    created_at: datetime
    last_seen: datetime | None
    visits: int


class _CredentialData(msgspec.Struct):
    credential_id: bytes  # msgspec uses standard base64
    user: str
    aaguid: str
    public_key: bytes  # msgspec uses standard base64
    sign_count: int
    created_at: datetime
    last_used: datetime | None
    last_verified: datetime | None


class _SessionData(msgspec.Struct):
    user: str
    credential: str
    host: str | None
    ip: str | None
    user_agent: str | None
    expiry: datetime


class _ResetTokenData(msgspec.Struct):
    user: str
    expiry: datetime
    token_type: str


class _DatabaseData(msgspec.Struct):
    permissions: dict[str, _PermissionData]
    orgs: dict[str, _OrgData]
    roles: dict[str, _RoleData]
    users: dict[str, _UserData]
    credentials: dict[str, _CredentialData]
    sessions: dict[str, _SessionData]
    reset_tokens: dict[str, _ResetTokenData]
