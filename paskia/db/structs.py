from datetime import datetime
from uuid import UUID

import msgspec


class Permission(msgspec.Struct, omit_defaults=True):
    uuid: UUID  # UUID primary key
    scope: str  # Permission scope identifier (e.g. "auth:admin", "myapp:write")
    display_name: str
    domain: str | None = None  # If set, scopes permission to this domain


class Role(msgspec.Struct):
    uuid: UUID
    org_uuid: UUID
    display_name: str
    permissions: list[str] = []  # permission UUIDs this role grants


class Org(msgspec.Struct):
    uuid: UUID
    display_name: str
    permissions: list[str] = []  # permission UUIDs this org can grant
    roles: list[Role] = []  # roles belonging to this org


class User(msgspec.Struct):
    uuid: UUID
    display_name: str
    role_uuid: UUID
    created_at: datetime | None = None
    last_seen: datetime | None = None
    visits: int = 0


class Credential(msgspec.Struct):
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
    key: str
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


class ResetToken(msgspec.Struct):
    key: bytes
    user_uuid: UUID
    expiry: datetime
    token_type: str


class SessionContext(msgspec.Struct):
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
    orgs: dict[UUID, bool] = {}  # org_uuid -> True (which orgs can grant this)


class _OrgData(msgspec.Struct):
    display_name: str
    created_at: datetime | None = None


class _RoleData(msgspec.Struct):
    org: UUID
    display_name: str
    permissions: dict[UUID, bool] = {}  # permission_uuid -> True


class _UserData(msgspec.Struct):
    display_name: str
    role: UUID
    created_at: datetime
    last_seen: datetime | None
    visits: int


class _CredentialData(msgspec.Struct):
    credential_id: bytes
    user: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None
    last_verified: datetime | None


class _SessionData(msgspec.Struct):
    user: UUID
    credential: UUID
    host: str | None
    ip: str | None
    user_agent: str | None
    expiry: datetime


class _ResetTokenData(msgspec.Struct):
    user: UUID
    expiry: datetime
    token_type: str


class _DatabaseData(msgspec.Struct, omit_defaults=True):
    permissions: dict[UUID, _PermissionData]
    orgs: dict[UUID, _OrgData]
    roles: dict[UUID, _RoleData]
    users: dict[UUID, _UserData]
    credentials: dict[UUID, _CredentialData]
    sessions: dict[str, _SessionData]
    reset_tokens: dict[bytes, _ResetTokenData]
    v: int = 0
