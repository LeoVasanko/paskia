from datetime import datetime, timezone
from uuid import UUID

import msgspec
import uuid7

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


class Role(msgspec.Struct, dict=True, omit_defaults=True):
    """Role data structure.

    Mutable fields: display_name, permissions
    Immutable fields: org (set at creation, never modified)
    uuid is generated at creation.
    """

    org: UUID
    display_name: str
    permissions: dict[UUID, bool] = {}  # permission_uuid -> True

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @property
    def permission_set(self) -> set[UUID]:
        """Get permissions as a set of UUIDs."""
        return set(self.permissions.keys())

    @classmethod
    def create(
        cls,
        org: UUID,
        display_name: str,
        permissions: set[UUID] | None = None,
    ) -> "Role":
        """Create a new Role with auto-generated uuid7."""
        role = cls(
            org=org,
            display_name=display_name,
            permissions={p: True for p in (permissions or set())},
        )
        role.uuid = uuid7.create()
        return role


class Org(msgspec.Struct, dict=True):
    """Organization data structure."""

    display_name: str

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @classmethod
    def create(cls, display_name: str) -> "Org":
        """Create a new Org with auto-generated uuid7."""
        org = cls(display_name=display_name)
        org.uuid = uuid7.create()
        return org


class User(msgspec.Struct, dict=True):
    """User data structure.

    Mutable fields: display_name, role, last_seen, visits
    Immutable fields: created_at (set at creation, never modified)
    uuid is derived from created_at using uuid7.
    """

    display_name: str
    role: UUID
    created_at: datetime
    last_seen: datetime | None = None
    visits: int = 0

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

    @classmethod
    def create(
        cls,
        display_name: str,
        role: UUID,
        created_at: datetime | None = None,
    ) -> "User":
        """Create a new User with auto-generated uuid7."""

        user = cls(
            display_name=display_name,
            role=role,
            created_at=created_at or datetime.now(timezone.utc),
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
    user: UUID
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None

    def __post_init__(self):
        self.uuid: UUID = _UUID_UNSET  # Convenience field, not serialized

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
    """Session data structure.

    Mutable fields: expiry (updated on session refresh)
    Immutable fields: user, credential, host, ip, user_agent
    key is stored in the dict key, not in the struct.
    """

    user: UUID
    credential: UUID
    host: str
    ip: str
    user_agent: str
    expiry: datetime

    def __post_init__(self):
        self.key: str = ""  # Convenience field, not serialized

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expiry": self.expiry.isoformat(),
        }


class ResetToken(msgspec.Struct, dict=True):
    """Reset/device-addition token data structure.

    Immutable fields: All fields (tokens are created and deleted, never modified)
    key is stored in the dict key, not in the struct.
    """

    user: UUID
    expiry: datetime
    token_type: str

    def __post_init__(self):
        self.key: bytes = b""  # Convenience field, not serialized


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
            user = self.users[s.user]
            role = self.roles[user.role]
            org = self.orgs[role.org]
            credential = self.credentials[s.credential]
        except KeyError:
            return None

        # Effective permissions: role's permissions that the org can grant
        # Also filter by domain if host is provided
        org_perm_uuids = {
            pid for pid, p in self.permissions.items() if org.uuid in p.orgs
        }
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
