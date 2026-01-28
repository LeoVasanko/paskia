from __future__ import annotations

import secrets
from datetime import UTC, datetime
from uuid import UUID

import msgspec
import uuid7

from paskia import db
from paskia.util.hostutil import normalize_host

# Sentinel for uuid fields before they are set by create() or DB post init
_UUID_UNSET = UUID(int=0)


class Permission(msgspec.Struct, dict=True, omit_defaults=True):
    """Permission data structure.

    Mutable fields: scope, display_name, domain, orgs
    Immutable fields: None (all fields can be updated via update_permission)
    uuid is generated at creation.
    """

    scope: str  # Permission scope identifier (e.g. "auth:admin", "myapp:write")
    display_name: str
    domain: str | None = None  # If set, scopes permission to this domain
    orgs: dict[UUID, bool] = {}  # org_uuid -> True (which orgs can grant this)

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @property
    def org_set(self) -> set[UUID]:
        """Get orgs that can grant this permission as a set."""
        return set(self.orgs.keys())

    @property
    def orgs_list(self) -> list[Org]:
        """Get list of Org objects that can grant this permission."""
        return [
            db.data().orgs[org_uuid]
            for org_uuid in self.orgs.keys()
            if org_uuid in db.data().orgs
        ]

    @classmethod
    def create(
        cls,
        scope: str,
        display_name: str,
        domain: str | None = None,
    ) -> Permission:
        """Create a new Permission with auto-generated uuid7."""
        perm = cls(
            scope=scope,
            display_name=display_name,
            domain=domain,
        )
        perm.uuid = uuid7.create()
        return perm


class Org(msgspec.Struct, dict=True):
    """Organization data structure."""

    display_name: str

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @property
    def roles(self) -> list[Role]:
        """Get all roles that belong to this organization."""
        return [r for r in db.data().roles.values() if r.org_uuid == self.uuid]

    @property
    def permissions(self) -> list[Permission]:
        """Get all permissions that this organization can grant."""
        return [p for p in db.data().permissions.values() if self.uuid in p.orgs]

    @classmethod
    def create(cls, display_name: str) -> Org:
        """Create a new Org with auto-generated uuid7."""
        org = cls(display_name=display_name)
        org.uuid = uuid7.create()
        return org


class Role(msgspec.Struct, dict=True, omit_defaults=True):
    """Role data structure.

    Mutable fields: display_name, permissions
    Immutable fields: org_uuid (set at creation, never modified)
    uuid is generated at creation.
    """

    org_uuid: UUID = msgspec.field(name="org")
    display_name: str
    permissions: dict[UUID, bool] = {}  # permission_uuid -> True

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @property
    def permission_set(self) -> set[UUID]:
        """Get permissions as a set of UUIDs."""
        return set(self.permissions.keys())

    @property
    def permissions_list(self) -> list[Permission]:
        """Get list of Permission objects for this role."""
        return [
            db.data().permissions[perm_uuid]
            for perm_uuid in self.permissions.keys()
            if perm_uuid in db.data().permissions
        ]

    @property
    def org(self) -> Org:
        """Get the organization object this role belongs to."""
        return db.data().orgs[self.org_uuid]

    @property
    def users(self) -> list[User]:
        """Get all users that have this role."""
        return [u for u in db.data().users.values() if u.role_uuid == self.uuid]

    @classmethod
    def create(
        cls,
        org: UUID | Org,
        display_name: str,
        permissions: set[UUID] | None = None,
    ) -> Role:
        """Create a new Role with auto-generated uuid7."""
        org_uuid = org if isinstance(org, UUID) else org.uuid
        role = cls(
            org_uuid=org_uuid,
            display_name=display_name,
            permissions={p: True for p in (permissions or set())},
        )
        role.uuid = uuid7.create()
        return role


class User(msgspec.Struct, dict=True):
    """User data structure.

    Mutable fields: display_name, role_uuid, last_seen, visits
    Immutable fields: created_at (set at creation, never modified)
    uuid is derived from created_at using uuid7.
    """

    display_name: str
    role_uuid: UUID = msgspec.field(name="role")
    created_at: datetime
    last_seen: datetime | None = None
    visits: int = 0

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @property
    def role(self) -> Role:
        """Get the role object this user has."""
        return db.data().roles[self.role_uuid]

    @property
    def org(self) -> Org:
        """Get the organization this user belongs to (via role)."""
        return self.role.org

    @property
    def credentials(self) -> list[Credential]:
        """Get all credentials for this user."""
        return [c for c in db.data().credentials.values() if c.user_uuid == self.uuid]

    @property
    def sessions(self) -> list[Session]:
        """Get all sessions for this user."""
        return [s for s in db.data().sessions.values() if s.user_uuid == self.uuid]

    @property
    def reset_tokens(self) -> list[ResetToken]:
        """Get all reset tokens for this user."""
        return [t for t in db.data().reset_tokens.values() if t.user_uuid == self.uuid]

    @classmethod
    def create(
        cls,
        display_name: str,
        role: UUID | Role,
        created_at: datetime | None = None,
    ) -> User:
        """Create a new User with auto-generated uuid7."""
        role_uuid = role if isinstance(role, UUID) else role.uuid
        user = cls(
            display_name=display_name,
            role_uuid=role_uuid,
            created_at=created_at or datetime.now(UTC),
        )
        user.uuid = uuid7.create(user.created_at)
        return user


class Credential(msgspec.Struct, dict=True):
    """Credential (passkey) data structure.

    Mutable fields: sign_count, last_used, last_verified
    Immutable fields: credential_id, user, aaguid, public_key, created_at
    uuid is derived from created_at using uuid7.
    """

    credential_id: bytes  # Long binary ID from the authenticator
    user_uuid: UUID = msgspec.field(name="user")
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @property
    def user(self) -> User:
        """Get the User object for this credential."""
        return db.data().users[self.user_uuid]

    @property
    def sessions(self) -> list[Session]:
        """Get all sessions using this credential."""
        return [
            s for s in db.data().sessions.values() if s.credential_uuid == self.uuid
        ]

    @classmethod
    def create(
        cls,
        credential_id: bytes,
        user: UUID | User,
        aaguid: UUID,
        public_key: bytes,
        sign_count: int,
        created_at: datetime | None = None,
    ) -> Credential:
        """Create a new Credential with auto-generated uuid7."""
        user_uuid = user if isinstance(user, UUID) else user.uuid
        now = created_at or datetime.now(UTC)
        cred = cls(
            credential_id=credential_id,
            user_uuid=user_uuid,
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
    """Session data structure.

    Mutable fields: expiry (updated on session refresh)
    Immutable fields: user_uuid, credential_uuid, host, ip, user_agent
    key is stored in the dict key, not in the struct.
    """

    user_uuid: UUID = msgspec.field(name="user")
    credential_uuid: UUID = msgspec.field(name="credential")
    host: str
    ip: str
    user_agent: str
    expiry: datetime

    def __post_init__(self):
        self.key: str = ""  # Convenience field, not serialized

    @property
    def user(self) -> User:
        """Get the User object for this session."""
        return db.data().users[self.user_uuid]

    @property
    def credential(self) -> Credential:
        """Get the Credential object for this session."""
        return db.data().credentials[self.credential_uuid]

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expiry": self.expiry.isoformat(),
        }

    @classmethod
    def create(
        cls,
        user: UUID | User,
        credential: UUID | Credential,
        host: str,
        ip: str,
        user_agent: str,
        expiry: datetime,
    ) -> Session:
        """Create a new Session with auto-generated key."""
        user_uuid = user if isinstance(user, UUID) else user.uuid
        credential_uuid = (
            credential if isinstance(credential, UUID) else credential.uuid
        )
        session = cls(
            user_uuid=user_uuid,
            credential_uuid=credential_uuid,
            host=host,
            ip=ip,
            user_agent=user_agent,
            expiry=expiry,
        )
        session.key = secrets.token_urlsafe(12)
        return session


class ResetToken(msgspec.Struct, dict=True):
    """Reset/device-addition token data structure.

    Immutable fields: All fields (tokens are created and deleted, never modified)
    key is stored in the dict key, not in the struct.
    """

    user_uuid: UUID = msgspec.field(name="user")
    expiry: datetime
    token_type: str

    def __post_init__(self):
        self.key: bytes = b""  # Convenience field, not serialized

    @property
    def user(self) -> User:
        """Get the User object for this reset token."""
        return db.data().users[self.user_uuid]


class SessionContext(msgspec.Struct):
    session: Session
    user: User
    org: Org
    role: Role
    credential: Credential
    permissions: list[Permission] = []


# -------------------------------------------------------------------------
# Database storage structure
# -------------------------------------------------------------------------


class DB(msgspec.Struct, dict=True, omit_defaults=False):
    """In-memory database. Access fields directly for reads."""

    permissions: dict[UUID, Permission] = {}
    orgs: dict[UUID, Org] = {}
    roles: dict[UUID, Role] = {}
    users: dict[UUID, User] = {}
    credentials: dict[UUID, Credential] = {}
    sessions: dict[str, Session] = {}
    reset_tokens: dict[bytes, ResetToken] = {}
    v: int = 0

    def __post_init__(self):
        # Store reference for persistence (not serialized)
        self._store = None
        # Set the key fields on all stored objects
        for uuid, perm in self.permissions.items():
            perm.uuid = uuid
        for uuid, org in self.orgs.items():
            org.uuid = uuid
        for uuid, role in self.roles.items():
            role.uuid = uuid
        for uuid, user in self.users.items():
            user.uuid = uuid
        for uuid, cred in self.credentials.items():
            cred.uuid = uuid
        for key, session in self.sessions.items():
            session.key = key
        for key, token in self.reset_tokens.items():
            token.key = key

    def transaction(self, action, ctx=None, *, user=None):
        """Wrap writes in transaction. Delegates to JsonlStore."""
        return self._store.transaction(action, ctx, user=user)

    def session_ctx(
        self, session_key: str, host: str | None = None
    ) -> SessionContext | None:
        """Get full session context with effective permissions.

        Args:
            session_key: The session key string
            host: Optional host for binding/validation and domain-scoped permissions

        Returns:
            SessionContext if valid, None if session not found, expired, or host mismatch
        """
        try:
            s = self.sessions[session_key]
        except KeyError:
            return None

        # Validate host matches (sessions are always created with a host)
        if s.host != host:
            # Session bound to different host
            return None

        try:
            user = s.user
            role = user.role
            org = role.org
            credential = s.credential
        except KeyError:
            return None

        # Effective permissions: role's permissions that the org can grant
        # Also filter by domain if host is provided
        org_perm_uuids = {p.uuid for p in org.permissions}
        normalized_host = normalize_host(host)
        host_without_port = (
            normalized_host.rsplit(":", 1)[0] if normalized_host else None
        )

        effective_perms = []
        for perm_uuid in role.permission_set:
            if perm_uuid not in org_perm_uuids:
                continue
            try:
                p = self.permissions[perm_uuid]
            except KeyError:
                continue
            # Check domain restriction
            if p.domain is not None and p.domain != host_without_port:
                continue
            effective_perms.append(p)

        return SessionContext(
            session=s,
            user=user,
            org=org,
            role=role,
            credential=credential,
            permissions=effective_perms,
        )
