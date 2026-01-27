from datetime import datetime
from uuid import UUID

import msgspec
import uuid7


class Permission(msgspec.Struct, dict=True, omit_defaults=True):
    scope: str  # Permission scope identifier (e.g. "auth:admin", "myapp:write")
    display_name: str
    domain: str | None = None  # If set, scopes permission to this domain
    orgs: dict[UUID, bool] = {}  # org_uuid -> True (which orgs can grant this)

    def __post_init__(self):
        self.uuid: UUID | None = None  # Convenience field, not serialized

    @classmethod
    def create(
        cls,
        scope: str,
        display_name: str,
        domain: str | None = None,
    ) -> "Permission":
        """Create a new Permission with auto-generated uuid7."""
        perm = cls(
            scope=scope,
            display_name=display_name,
            domain=domain,
        )
        perm.uuid = uuid7.create()
        return perm


class Role(msgspec.Struct, dict=True):
    org: UUID
    display_name: str
    permissions: list[str] = []  # permission UUIDs this role grants

    def __post_init__(self):
        self.uuid: UUID | None = None  # Convenience field, not serialized

    @classmethod
    def create(
        cls,
        org: UUID,
        display_name: str,
        permissions: list[str] | None = None,
    ) -> "Role":
        """Create a new Role with auto-generated uuid7."""
        role = cls(
            org=org,
            display_name=display_name,
            permissions=permissions or [],
        )
        role.uuid = uuid7.create()
        return role

    # Legacy alias for org field
    @property
    def org_uuid(self) -> UUID:
        return self.org


class Org(msgspec.Struct, dict=True):
    display_name: str
    permissions: list[str] = []  # permission UUIDs this org can grant
    roles: list[Role] = []  # roles belonging to this org

    def __post_init__(self):
        self.uuid: UUID | None = None  # Convenience field, not serialized

    @classmethod
    def create(
        cls,
        display_name: str,
        permissions: list[str] | None = None,
    ) -> "Org":
        """Create a new Org with auto-generated uuid7."""
        org = cls(
            display_name=display_name,
            permissions=permissions or [],
        )
        org.uuid = uuid7.create()
        return org


class User(msgspec.Struct, dict=True):
    display_name: str
    role: UUID
    created_at: datetime
    last_seen: datetime | None = None
    visits: int = 0

    def __post_init__(self):
        self.uuid: UUID | None = None  # Convenience field, not serialized

    @classmethod
    def create(
        cls,
        display_name: str,
        role: UUID,
        created_at: datetime | None = None,
    ) -> "User":
        """Create a new User with auto-generated uuid7."""
        from datetime import timezone

        user = cls(
            display_name=display_name,
            role=role,
            created_at=created_at or datetime.now(timezone.utc),
        )
        user.uuid = uuid7.create(user.created_at)
        return user


class Credential(msgspec.Struct, dict=True):
    credential_id: bytes  # Long binary ID from the authenticator
    user: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None

    def __post_init__(self):
        self.uuid: UUID | None = None  # Convenience field, not serialized

    @classmethod
    def create(
        cls,
        credential_id: bytes,
        user: UUID,
        aaguid: UUID,
        public_key: bytes,
        sign_count: int,
        created_at: datetime | None = None,
    ) -> "Credential":
        """Create a new Credential with auto-generated uuid7."""
        from datetime import timezone

        now = created_at or datetime.now(timezone.utc)
        cred = cls(
            credential_id=credential_id,
            user=user,
            aaguid=aaguid,
            public_key=public_key,
            sign_count=sign_count,
            created_at=now,
            last_used=now,
            last_verified=now,
        )
        cred.uuid = uuid7.create(now)
        return cred


class Session(msgspec.Struct, dict=True):
    user: UUID
    credential: UUID
    host: str | None
    ip: str | None
    user_agent: str | None
    expiry: datetime

    def __post_init__(self):
        self.key: str | None = None  # Convenience field, not serialized

    # Legacy aliases
    @property
    def user_uuid(self) -> UUID:
        return self.user

    @property
    def credential_uuid(self) -> UUID:
        return self.credential

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expiry": self.expiry.isoformat(),
        }


class ResetToken(msgspec.Struct, dict=True):
    user: UUID
    expiry: datetime
    token_type: str

    def __post_init__(self):
        self.key: bytes | None = None  # Convenience field, not serialized

    # Legacy alias
    @property
    def user_uuid(self) -> UUID:
        return self.user


class SessionContext(msgspec.Struct):
    session: Session
    user: User
    org: Org
    role: Role
    credential: Credential
    permissions: list[Permission] = []


# -------------------------------------------------------------------------
# Internal storage types (different structure for efficient storage)
# -------------------------------------------------------------------------


class _OrgData(msgspec.Struct):
    display_name: str
    created_at: datetime | None = None


class _RoleData(msgspec.Struct):
    org: UUID
    display_name: str
    permissions: dict[UUID, bool] = {}  # permission_uuid -> True


class _DatabaseData(msgspec.Struct, omit_defaults=True):
    permissions: dict[UUID, Permission]
    orgs: dict[UUID, _OrgData]
    roles: dict[UUID, _RoleData]
    users: dict[UUID, User]
    credentials: dict[UUID, Credential]
    sessions: dict[str, Session]
    reset_tokens: dict[bytes, ResetToken]
    v: int = 0
