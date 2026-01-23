"""
Async JSON database implementation for WebAuthn passkey authentication.

This module provides a JSON file-based database layer that maintains all data
in memory and persists changes to disk as JSONL. Uses object keys by UUID
instead of lists for efficient lookups.

All public data types are msgspec Structs for efficient serialization.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import base64url
import jsondiff
import msgspec

from paskia.config import SESSION_LIFETIME

DB_PATH_DEFAULT = "paskia.jsonl"


# -------------------------------------------------------------------------
# Public data types (msgspec Structs)
# -------------------------------------------------------------------------


class Permission(msgspec.Struct):
    """A permission that can be granted to roles."""

    id: str  # String primary key (max 128 chars)
    display_name: str


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
    renewed: datetime

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "renewed": self.renewed.isoformat(),
        }


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


class _PermissionData(msgspec.Struct):
    display_name: str
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
    renewed: datetime


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


class _ChangeRecord(msgspec.Struct):
    """A single change record in the JSONL file."""

    ts: datetime
    actor: str
    diff: dict


# msgspec encoder/decoder with built-in conversions
# datetime -> ISO 8601 strings, bytes -> standard base64
_json_encoder = msgspec.json.Encoder()
_json_decoder = msgspec.json.Decoder(_DatabaseData)


def _bytes_to_str(b: bytes | None) -> str | None:
    """Convert bytes to base64url string."""
    if b is None:
        return None
    return base64url.enc(b)


def _str_to_bytes(s: str | None) -> bytes | None:
    """Convert base64url string to bytes."""
    if s is None:
        return None
    return base64url.dec(s)


# Global database instance (set by init())
_db: "DB | None" = None


def get_db() -> "DB":
    """Get the global database instance."""
    if _db is None:
        raise RuntimeError("Database not initialized. Call init() first.")
    return _db


async def init(*args, **kwargs):
    """Initialize the global database instance."""
    global _db
    db_path = os.environ.get("PASKIA_DB", DB_PATH_DEFAULT)
    # Remove any prefix (for compatibility with SQL-style URIs)
    if db_path.startswith("json:"):
        db_path = db_path[5:]
    _db = DB(db_path)
    await _db.init_db()


class DB:
    """JSON-based database implementation.

    Maintains data in memory and persists to disk on every change.
    Uses nested dictionaries keyed by UUID strings for efficient lookup.

    Data structure:
        {
            "permissions": { "<id>": {"id": ..., "display_name": ...} },
            "orgs": { "<uuid>": {..., "permissions": [...]} },
            "roles": { "<uuid>": {..., "permissions": [...]} },
            "users": { "<uuid>": {...} },
            "credentials": { "<uuid>": {...} },
            "sessions": { "<b64 key>": {...} },
            "reset_tokens": { "<b64 key>": {...} },
        }
    """

    def __init__(self, db_path: str = DB_PATH_DEFAULT):
        """Initialize with database file path."""
        self.db_path = Path(db_path)
        self._data: _DatabaseData | None = None
        self._previous_builtins: dict[str, Any] = {}  # For diffing (JSON-compatible)
        self._lock = asyncio.Lock()

    def _empty_data(self) -> _DatabaseData:
        """Return an empty database structure."""
        return _DatabaseData(
            permissions={},
            orgs={},
            roles={},
            users={},
            credentials={},
            sessions={},
            reset_tokens={},
        )

    async def _load(self) -> None:
        """Load data from disk by applying change log.

        Replays all changes from JSONL file using plain dicts (to handle
        schema evolution), then validates the final state against msgspec
        structs which become the working copy with proper datetime types.
        """
        data_dict = msgspec.to_builtins(self._empty_data())
        if self.db_path.exists():
            try:
                # Read JSONL file line by line and apply diffs
                with open(self.db_path, encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            change = msgspec.json.decode(line.encode("utf-8"))
                            # Apply the diff to current state (marshal=True for $-prefixed keys)
                            data_dict = jsondiff.patch(
                                data_dict, change["diff"], marshal=True
                            )
                        except Exception as e:
                            raise ValueError(f"Error parsing line {line_num}: {e}")
            except (OSError, ValueError, msgspec.DecodeError) as e:
                raise ValueError(f"Failed to load database: {e}")

        # Validate and convert to msgspec struct (datetime strings -> datetime objects)
        self._data = _json_decoder.decode(_json_encoder.encode(data_dict))
        # Store builtins representation for diffing (to_builtins creates a copy)
        self._previous_builtins = msgspec.to_builtins(self._data)

    async def _save(self, actor: str = "system") -> None:
        """Append change record to JSONL file."""
        if self._data is None:
            return
        # Convert current struct to builtins for diffing (datetime->str, bytes->base64)
        current_builtins = msgspec.to_builtins(self._data)

        # Calculate diff between previous and current state (marshal=True for JSON-serializable keys)
        diff = jsondiff.diff(self._previous_builtins, current_builtins, marshal=True)

        # Only save if there are changes
        if diff:
            change_record = _ChangeRecord(
                ts=datetime.now(timezone.utc),
                actor=actor,
                diff=diff,
            )

            # Encode and append to file
            data = _json_encoder.encode(change_record)
            line = data.decode("utf-8") + "\n"

            # Append atomically (create temp file, then append)
            tmp_path = self.db_path.with_suffix(".tmp")
            try:
                # Read existing content
                existing_content = ""
                if self.db_path.exists():
                    existing_content = await asyncio.to_thread(
                        self.db_path.read_text, "utf-8"
                    )

                # Append new line
                new_content = existing_content + line

                # Write to temp file and rename
                await asyncio.to_thread(tmp_path.write_text, new_content, "utf-8")
                await asyncio.to_thread(tmp_path.replace, self.db_path)

                # Update previous builtins for next diff (to_builtins creates a copy)
                self._previous_builtins = current_builtins
            except OSError:
                # Clean up temp file on error
                if tmp_path.exists():
                    await asyncio.to_thread(tmp_path.unlink)

    @asynccontextmanager
    async def session(self):
        """Context manager for atomic operations with save on exit."""
        async with self._lock:
            yield
            await self._save()

    async def init_db(self) -> None:
        """Initialize database (load from disk)."""
        async with self._lock:
            await self._load()

    # -------------------------------------------------------------------------
    # User operations
    # -------------------------------------------------------------------------

    async def get_user_by_uuid(self, user_uuid: UUID) -> User:
        async with self._lock:
            key = str(user_uuid)
            if key not in self._data.users:
                raise ValueError("User not found")
            u = self._data.users[key]
            return User(
                uuid=user_uuid,  # Use the key directly
                display_name=u.display_name,
                role_uuid=UUID(u.role),
                created_at=u.created_at,
                last_seen=u.last_seen,
                visits=u.visits,
            )

    async def create_user(self, user: User) -> None:
        async with self.session():
            key = str(user.uuid)
            self._data.users[key] = _UserData(
                display_name=user.display_name,
                role=str(user.role_uuid),
                created_at=user.created_at or datetime.now(timezone.utc),
                last_seen=user.last_seen,
                visits=user.visits,
            )

    async def update_user_display_name(
        self, user_uuid: UUID, display_name: str
    ) -> None:
        async with self.session():
            key = str(user_uuid)
            if key not in self._data.users:
                raise ValueError("User not found")
            self._data.users[key].display_name = display_name

    # -------------------------------------------------------------------------
    # Role operations
    # -------------------------------------------------------------------------

    async def create_role(self, role: Role) -> None:
        async with self.session():
            key = str(role.uuid)
            self._data.roles[key] = _RoleData(
                org=str(role.org_uuid),
                display_name=role.display_name,
                permissions={p: True for p in role.permissions}
                if role.permissions
                else {},
            )

    async def update_role(self, role: Role) -> None:
        async with self.session():
            key = str(role.uuid)
            if key not in self._data.roles:
                raise ValueError("Role not found")
            self._data.roles[key].display_name = role.display_name
            self._data.roles[key].permissions = (
                {p: True for p in role.permissions} if role.permissions else {}
            )

    async def delete_role(self, role_uuid: UUID) -> None:
        async with self.session():
            key = str(role_uuid)
            # Check for users with this role
            for u in self._data.users.values():
                if u.role == key:
                    raise ValueError("Cannot delete role with assigned users")
            if key in self._data.roles:
                del self._data.roles[key]

    async def get_role(self, role_uuid: UUID) -> Role:
        async with self._lock:
            key = str(role_uuid)
            if key not in self._data.roles:
                raise ValueError("Role not found")
            r = self._data.roles[key]
            return Role(
                uuid=role_uuid,  # Use the key directly
                org_uuid=UUID(r.org),
                display_name=r.display_name,
                permissions=list(r.permissions),
            )

    # -------------------------------------------------------------------------
    # Credential operations
    # -------------------------------------------------------------------------

    async def create_credential(self, credential: Credential) -> None:
        async with self.session():
            key = str(credential.uuid)
            self._data.credentials[key] = _CredentialData(
                credential_id=credential.credential_id,  # Store bytes directly
                user=str(credential.user_uuid),
                aaguid=str(credential.aaguid),
                public_key=credential.public_key,  # Store bytes directly
                sign_count=credential.sign_count,
                created_at=credential.created_at,
                last_used=credential.last_used,
                last_verified=credential.last_verified,
            )

    async def get_credential_by_id(self, credential_id: bytes) -> Credential:
        async with self._lock:
            for key, c in self._data.credentials.items():
                if c.credential_id == credential_id:
                    return Credential(
                        uuid=UUID(key),  # Use the key directly
                        credential_id=c.credential_id,  # Already bytes
                        user_uuid=UUID(c.user),
                        aaguid=UUID(c.aaguid),
                        public_key=c.public_key,  # Already bytes
                        sign_count=c.sign_count,
                        created_at=c.created_at,  # Already datetime
                        last_used=c.last_used,
                        last_verified=c.last_verified,
                    )
            raise ValueError("Credential not found")

    async def get_credentials_by_user_uuid(self, user_uuid: UUID) -> list[bytes]:
        async with self._lock:
            user_key = str(user_uuid)
            result: list[bytes] = []
            for c in self._data.credentials.values():
                if c.user == user_key:
                    cred_id = c.credential_id
                    if cred_id is not None:
                        result.append(cred_id)
            return result

    async def update_credential(self, credential: Credential) -> None:
        async with self.session():
            for key, c in self._data.credentials.items():
                if c.credential_id == credential.credential_id:
                    c.sign_count = credential.sign_count
                    c.created_at = credential.created_at
                    c.last_used = credential.last_used
                    c.last_verified = credential.last_verified
                    return
            raise ValueError("Credential not found")

    async def delete_credential(self, uuid: UUID, user_uuid: UUID) -> None:
        async with self.session():
            key = str(uuid)
            if key not in self._data.credentials:
                return
            c = self._data.credentials[key]
            if c.user != str(user_uuid):
                return
            del self._data.credentials[key]

    # -------------------------------------------------------------------------
    # Session operations
    # -------------------------------------------------------------------------

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
        async with self.session():
            key_b64 = _bytes_to_str(key)
            self._data.sessions[key_b64] = _SessionData(
                user=str(user_uuid),
                credential=str(credential_uuid),
                host=host,
                ip=ip,
                user_agent=user_agent,
                renewed=renewed,
            )

    async def get_session(self, key: bytes) -> Session | None:
        async with self._lock:
            key_b64 = _bytes_to_str(key)
            if key_b64 not in self._data.sessions:
                return None
            s = self._data.sessions[key_b64]
            return Session(
                key=_str_to_bytes(key_b64),  # type: ignore[arg-type]
                user_uuid=UUID(s.user),
                credential_uuid=UUID(s.credential),
                host=s.host,
                ip=s.ip,
                user_agent=s.user_agent,
                renewed=s.renewed,  # Already datetime
            )

    async def delete_session(self, key: bytes) -> None:
        async with self.session():
            key_b64 = _bytes_to_str(key)
            if key_b64 in self._data.sessions:
                del self._data.sessions[key_b64]

    async def update_session(
        self,
        key: bytes,
        *,
        ip: str,
        user_agent: str,
        renewed: datetime,
    ) -> Session | None:
        async with self.session():
            key_b64 = _bytes_to_str(key)
            if key_b64 not in self._data.sessions:
                return None
            s = self._data.sessions[key_b64]
            s.ip = ip
            s.user_agent = user_agent
            s.renewed = renewed
            return Session(
                key=_str_to_bytes(key_b64),  # type: ignore[arg-type]
                user_uuid=UUID(s.user),
                credential_uuid=UUID(s.credential),
                host=s.host,
                ip=s.ip,
                user_agent=s.user_agent,
                renewed=s.renewed,  # Already datetime
            )

    async def set_session_host(self, key: bytes, host: str) -> None:
        async with self.session():
            key_b64 = _bytes_to_str(key)
            if key_b64 in self._data.sessions:
                s = self._data.sessions[key_b64]
                if s.host is None:
                    s.host = host

    async def list_sessions_for_user(self, user_uuid: UUID) -> list[Session]:
        async with self._lock:
            user_key = str(user_uuid)
            sessions = []
            for key_b64, s in self._data.sessions.items():
                if s.user == user_key:
                    key_bytes = _str_to_bytes(key_b64)
                    if key_bytes and key_bytes.startswith(b"sess"):
                        sessions.append(
                            Session(
                                key=key_bytes,
                                user_uuid=UUID(s.user),
                                credential_uuid=UUID(s.credential),
                                host=s.host,
                                ip=s.ip,
                                user_agent=s.user_agent,
                                renewed=s.renewed,  # Already datetime
                            )
                        )
            # Sort by renewed desc
            sessions.sort(key=lambda x: x.renewed, reverse=True)
            return sessions

    async def delete_sessions_for_user(self, user_uuid: UUID) -> None:
        async with self.session():
            user_key = str(user_uuid)
            to_delete = [
                k for k, s in self._data.sessions.items() if s.user == user_key
            ]
            for k in to_delete:
                del self._data.sessions[k]

    # -------------------------------------------------------------------------
    # Reset token operations
    # -------------------------------------------------------------------------

    async def create_reset_token(
        self,
        user_uuid: UUID,
        key: bytes,
        expiry: datetime,
        token_type: str,
    ) -> None:
        async with self.session():
            key_b64 = _bytes_to_str(key)
            self._data.reset_tokens[key_b64] = _ResetTokenData(
                user=str(user_uuid),
                expiry=expiry,
                token_type=token_type,
            )

    async def get_reset_token(self, key: bytes) -> ResetToken | None:
        async with self._lock:
            key_b64 = _bytes_to_str(key)
            if key_b64 not in self._data.reset_tokens:
                return None
            t = self._data.reset_tokens[key_b64]
            return ResetToken(
                key=_str_to_bytes(key_b64),  # type: ignore[arg-type]
                user_uuid=UUID(t.user),
                expiry=t.expiry,  # Already datetime
                token_type=t.token_type,
            )

    async def delete_reset_token(self, key: bytes) -> None:
        async with self.session():
            key_b64 = _bytes_to_str(key)
            if key_b64 in self._data.reset_tokens:
                del self._data.reset_tokens[key_b64]

    # -------------------------------------------------------------------------
    # Organization operations
    # -------------------------------------------------------------------------

    async def create_organization(self, org: Org) -> None:
        async with self.session():
            key = str(org.uuid)
            self._data.orgs[key] = _OrgData(
                display_name=org.display_name,
            )

            # Update permissions to allow this org to grant them
            for perm_id in org.permissions:
                if perm_id in self._data.permissions:
                    self._data.permissions[perm_id].orgs[key] = True

            # Automatically create an organization admin permission if not present
            auto_perm_id = f"auth:org:{org.uuid}"
            if auto_perm_id not in self._data.permissions:
                self._data.permissions[auto_perm_id] = _PermissionData(
                    display_name=f"{org.display_name} Admin",
                    orgs={key: True},  # This org can grant its own admin permission
                )
            else:
                # Ensure this org can grant its own admin permission
                self._data.permissions[auto_perm_id].orgs[key] = True
            # Reflect the automatically added permission in the dataclass instance
            if auto_perm_id not in org.permissions:
                org.permissions.append(auto_perm_id)

    async def get_organization(self, org_id: str) -> Org:
        async with self._lock:
            # org_id is a UUID string
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            o = self._data.orgs[org_id]
            # Get permissions that this org can grant
            permissions = []
            for perm_id, p in self._data.permissions.items():
                if org_id in p.orgs:
                    permissions.append(perm_id)
            org = Org(
                uuid=UUID(org_id),  # Use the key directly
                display_name=o.display_name,
                permissions=permissions,
            )
            # Load roles for this org
            roles = []
            for role_uuid_str, r in self._data.roles.items():
                if r.org == org_id:
                    roles.append(
                        Role(
                            uuid=UUID(role_uuid_str),  # Use the key directly
                            org_uuid=UUID(r.org),
                            display_name=r.display_name,
                            permissions=list(r.permissions),
                        )
                    )
            org.roles = roles
            return org

    async def list_organizations(self) -> list[Org]:
        async with self._lock:
            orgs = []
            for org_uuid_str, o in self._data.orgs.items():
                # Get permissions that this org can grant
                permissions = []
                for perm_id, p in self._data.permissions.items():
                    if org_uuid_str in p.orgs:
                        permissions.append(perm_id)
                org = Org(
                    uuid=UUID(org_uuid_str),  # Use the key directly
                    display_name=o.display_name,
                    permissions=permissions,
                )
                # Load roles for this org
                roles = []
                for role_uuid_str, r in self._data.roles.items():
                    if r.org == org_uuid_str:
                        roles.append(
                            Role(
                                uuid=UUID(role_uuid_str),  # Use the key directly
                                org_uuid=UUID(r.org),
                                display_name=r.display_name,
                                permissions=list(r.permissions),
                            )
                        )
                org.roles = roles
                orgs.append(org)
            return orgs

    async def update_organization(self, org: Org) -> None:
        async with self.session():
            key = str(org.uuid)
            if key not in self._data.orgs:
                raise ValueError("Organization not found")
            self._data.orgs[key].display_name = org.display_name
            # Update which permissions this org can grant
            # First remove this org from all permissions
            for p in self._data.permissions.values():
                if key in p.orgs:
                    del p.orgs[key]
            # Then add this org to the specified permissions
            for perm_id in org.permissions:
                if perm_id in self._data.permissions:
                    self._data.permissions[perm_id].orgs[key] = True

    async def delete_organization(self, org_uuid: UUID) -> None:
        async with self.session():
            key = str(org_uuid)
            if key in self._data.orgs:
                del self._data.orgs[key]
            # Cascade delete roles belonging to this org
            to_delete = [k for k, r in self._data.roles.items() if r.org == key]
            for k in to_delete:
                del self._data.roles[k]

    async def add_user_to_organization(
        self, user_uuid: UUID, org_id: str, role: str
    ) -> None:
        async with self.session():
            user_key = str(user_uuid)
            if user_key not in self._data.users:
                raise ValueError("User not found")
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            # Find role by display_name in org
            role_uuid = None
            for role_key, r in self._data.roles.items():
                if r.org == org_id and r.display_name == role:
                    role_uuid = role_key
                    break
            if role_uuid is None:
                raise ValueError("Role not found in organization")
            self._data.users[user_key].role = role_uuid

    async def transfer_user_to_organization(
        self, user_uuid: UUID, new_org_id: str, new_role: str | None = None
    ) -> None:
        raise ValueError("Users cannot be transferred to a different organization")

    async def get_user_organization(self, user_uuid: UUID) -> tuple[Org, str]:
        async with self._lock:
            user_key = str(user_uuid)
            if user_key not in self._data.users:
                raise ValueError("User not found")
            role_uuid = self._data.users[user_key].role
            if role_uuid not in self._data.roles:
                raise ValueError("Role not found")
            r = self._data.roles[role_uuid]
            org_uuid = r.org
            if org_uuid not in self._data.orgs:
                raise ValueError("Organization not found")
            o = self._data.orgs[org_uuid]
            org = Org(
                uuid=UUID(org_uuid),
                display_name=o.display_name,
                permissions=[],  # Could populate from permissions if needed
            )
            return org, r.display_name

    async def get_organization_users(self, org_id: str) -> list[tuple[User, str]]:
        async with self._lock:
            # Get all roles for this org
            org_role_uuids = {
                role_uuid_str
                for role_uuid_str, r in self._data.roles.items()
                if r.org == org_id
            }
            results = []
            for user_uuid_str, u in self._data.users.items():
                if u.role in org_role_uuids:
                    role_name = self._data.roles[u.role].display_name
                    user = User(
                        uuid=UUID(user_uuid_str),
                        display_name=u.display_name,
                        role_uuid=UUID(u.role),
                        created_at=u.created_at,
                        last_seen=u.last_seen,
                        visits=u.visits,
                    )
                    results.append((user, role_name))
            return results

    async def get_roles_by_organization(self, org_id: str) -> list[Role]:
        async with self._lock:
            roles = []
            for role_uuid_str, r in self._data.roles.items():
                if r.org == org_id:
                    roles.append(
                        Role(
                            uuid=UUID(role_uuid_str),  # Use the key directly
                            org_uuid=UUID(r.org),
                            display_name=r.display_name,
                            permissions=list(r.permissions),
                        )
                    )
            return roles

    async def get_user_role_in_organization(
        self, user_uuid: UUID, org_id: str
    ) -> str | None:
        async with self._lock:
            user_key = str(user_uuid)
            if user_key not in self._data.users:
                return None
            role_uuid = self._data.users[user_key].role
            if role_uuid not in self._data.roles:
                return None
            r = self._data.roles[role_uuid]
            if r.org != org_id:
                return None
            return r.display_name

    async def update_user_role_in_organization(
        self, user_uuid: UUID, new_role: str
    ) -> None:
        async with self.session():
            user_key = str(user_uuid)
            if user_key not in self._data.users:
                raise ValueError("User not found")
            current_role_uuid = self._data.users[user_key].role
            if current_role_uuid not in self._data.roles:
                raise ValueError("Current role not found")
            org_uuid = self._data.roles[current_role_uuid].org
            # Find new role
            new_role_uuid = None
            for role_uuid_str, r in self._data.roles.items():
                if r.org == org_uuid and r.display_name == new_role:
                    new_role_uuid = role_uuid_str
                    break
            if new_role_uuid is None:
                raise ValueError("Role not found in user's organization")
            self._data.users[user_key].role = new_role_uuid

    # -------------------------------------------------------------------------
    # Permission operations
    # -------------------------------------------------------------------------

    async def create_permission(self, permission: Permission) -> None:
        async with self.session():
            self._data.permissions[permission.id] = _PermissionData(
                display_name=permission.display_name,
                orgs={},  # Will be populated when orgs are allowed to grant this permission
            )

    async def get_permission(self, permission_id: str) -> Permission:
        async with self._lock:
            if permission_id not in self._data.permissions:
                raise ValueError("Permission not found")
            p = self._data.permissions[permission_id]
            return Permission(id=permission_id, display_name=p.display_name)

    async def list_permissions(self) -> list[Permission]:
        async with self._lock:
            return [
                Permission(id=pid, display_name=p.display_name)
                for pid, p in self._data.permissions.items()
            ]

    async def update_permission(self, permission: Permission) -> None:
        async with self.session():
            if permission.id not in self._data.permissions:
                raise ValueError("Permission not found")
            self._data.permissions[permission.id].display_name = permission.display_name

    async def delete_permission(self, permission_id: str) -> None:
        async with self.session():
            if permission_id in self._data.permissions:
                del self._data.permissions[permission_id]
            # Remove from roles (permissions is a dict)
            for r in self._data.roles.values():
                if permission_id in r.permissions:
                    del r.permissions[permission_id]

    async def rename_permission(
        self, old_id: str, new_id: str, display_name: str
    ) -> None:
        async with self.session():
            if old_id == new_id:
                if old_id in self._data.permissions:
                    self._data.permissions[old_id].display_name = display_name
                return
            if old_id not in self._data.permissions:
                raise ValueError("Original permission not found")
            if new_id in self._data.permissions:
                raise ValueError("New permission id already exists")

            # Create new permission with same orgs
            old_perm = self._data.permissions[old_id]
            self._data.permissions[new_id] = _PermissionData(
                display_name=display_name,
                orgs=dict(old_perm.orgs),
            )
            # Update role references (roles store permissions as dict)
            for r in self._data.roles.values():
                if old_id in r.permissions:
                    del r.permissions[old_id]
                    r.permissions[new_id] = True
            # Delete old permission
            del self._data.permissions[old_id]

    async def add_permission_to_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        async with self.session():
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            if permission_id not in self._data.permissions:
                raise ValueError("Permission not found")
            self._data.permissions[permission_id].orgs[org_id] = True

    async def remove_permission_from_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        async with self.session():
            if permission_id in self._data.permissions:
                orgs = self._data.permissions[permission_id].orgs
                if org_id in orgs:
                    del orgs[org_id]

    async def get_organization_permissions(self, org_id: str) -> list[Permission]:
        async with self._lock:
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            permissions = []
            for pid, p in self._data.permissions.items():
                if org_id in p.orgs:
                    permissions.append(Permission(id=pid, display_name=p.display_name))
            return permissions

    async def get_permission_organizations(self, permission_id: str) -> list[Org]:
        async with self._lock:
            if permission_id not in self._data.permissions:
                return []
            org_ids = self._data.permissions[permission_id].orgs
            orgs = []
            for org_id in org_ids:
                if org_id in self._data.orgs:
                    o = self._data.orgs[org_id]
                    # Get permissions for this org
                    permissions = []
                    for pid, p in self._data.permissions.items():
                        if org_id in p.orgs:
                            permissions.append(pid)
                    orgs.append(
                        Org(
                            uuid=UUID(org_id),
                            display_name=o.display_name,
                            permissions=permissions,
                        )
                    )
            return orgs

    # -------------------------------------------------------------------------
    # Role-permission operations
    # -------------------------------------------------------------------------

    async def add_permission_to_role(self, role_uuid: UUID, permission_id: str) -> None:
        async with self.session():
            key = str(role_uuid)
            if key not in self._data.roles:
                raise ValueError("Role not found")
            if permission_id not in self._data.permissions:
                raise ValueError("Permission not found")
            self._data.roles[key].permissions[permission_id] = True

    async def remove_permission_from_role(
        self, role_uuid: UUID, permission_id: str
    ) -> None:
        async with self.session():
            key = str(role_uuid)
            if key in self._data.roles:
                if permission_id in self._data.roles[key].permissions:
                    del self._data.roles[key].permissions[permission_id]

    async def get_role_permissions(self, role_uuid: UUID) -> list[Permission]:
        async with self._lock:
            key = str(role_uuid)
            if key not in self._data.roles:
                return []
            perm_ids = list(self._data.roles[key].permissions)
            permissions = []
            for pid in perm_ids:
                if pid in self._data.permissions:
                    p = self._data.permissions[pid]
                    permissions.append(Permission(id=pid, display_name=p.display_name))
            return permissions

    async def get_permission_roles(self, permission_id: str) -> list[Role]:
        async with self._lock:
            roles = []
            for role_uuid_str, r in self._data.roles.items():
                if permission_id in r.permissions:
                    roles.append(
                        Role(
                            uuid=UUID(role_uuid_str),  # Use the key directly
                            org_uuid=UUID(r.org),
                            display_name=r.display_name,
                            permissions=list(r.permissions),
                        )
                    )
            return roles

    # -------------------------------------------------------------------------
    # Combined operations
    # -------------------------------------------------------------------------

    async def login(self, user_uuid: UUID, credential: Credential) -> None:
        async with self.session():
            # Update credential
            for key, c in self._data.credentials.items():
                if c.credential_id == credential.credential_id:
                    c.sign_count = credential.sign_count
                    c.created_at = credential.created_at
                    c.last_used = credential.last_used
                    c.last_verified = credential.last_verified
                    break

            # Update user
            user_key = str(user_uuid)
            if user_key in self._data.users:
                self._data.users[user_key].last_seen = credential.last_used
                self._data.users[user_key].visits = (
                    self._data.users[user_key].visits + 1
                )

    async def create_user_and_credential(
        self, user: User, credential: Credential
    ) -> None:
        async with self.session():
            # Create user
            user_key = str(user.uuid)
            self._data.users[user_key] = _UserData(
                display_name=user.display_name,
                role=str(user.role_uuid),
                created_at=user.created_at or datetime.now(timezone.utc),
                last_seen=user.last_seen,
                visits=user.visits,
            )
            # Create credential
            cred_key = str(credential.uuid)
            self._data.credentials[cred_key] = _CredentialData(
                credential_id=credential.credential_id,  # Store bytes directly
                user=str(credential.user_uuid),
                aaguid=str(credential.aaguid),
                public_key=credential.public_key,  # Store bytes directly
                sign_count=credential.sign_count,
                created_at=credential.created_at,
                last_used=credential.last_used,
                last_verified=credential.last_verified,
            )

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
        async with self.session():
            user_key = str(user_uuid)
            # Ensure credential has last_used / last_verified
            if credential.last_used is None:
                credential.last_used = credential.created_at
            if credential.last_verified is None:
                credential.last_verified = credential.last_used

            # Insert credential
            cred_key = str(credential.uuid)
            self._data.credentials[cred_key] = _CredentialData(
                credential_id=credential.credential_id,  # Store bytes directly
                user=str(credential.user_uuid),
                aaguid=str(credential.aaguid),
                public_key=credential.public_key,  # Store bytes directly
                sign_count=credential.sign_count,
                created_at=credential.created_at,
                last_used=credential.last_used,
                last_verified=credential.last_verified,
            )

            # Delete old reset token if provided
            if reset_key:
                reset_key_b64 = _bytes_to_str(reset_key)
                if reset_key_b64 in self._data.reset_tokens:
                    del self._data.reset_tokens[reset_key_b64]

            # Optional rename
            if display_name and user_key in self._data.users:
                self._data.users[user_key].display_name = display_name

            # New session
            sess_key_b64 = _bytes_to_str(session_key)
            self._data.sessions[sess_key_b64] = _SessionData(
                user=user_key,
                credential=cred_key,
                host=host,
                ip=ip,
                user_agent=user_agent,
                renewed=credential.last_used,
            )

            # Login side-effects
            if user_key in self._data.users:
                self._data.users[user_key].last_seen = credential.last_used
                self._data.users[user_key].visits = (
                    self._data.users[user_key].visits + 1
                )

    async def cleanup(self) -> None:
        async with self.session():
            current_time = datetime.now(timezone.utc)
            session_threshold = current_time - SESSION_LIFETIME

            # Clean expired sessions
            to_delete_sessions = []
            for k, s in self._data.sessions.items():
                renewed = s.renewed
                if renewed and renewed < session_threshold:
                    to_delete_sessions.append(k)
            for k in to_delete_sessions:
                del self._data.sessions[k]

            # Clean expired reset tokens
            to_delete_tokens = []
            for k, t in self._data.reset_tokens.items():
                expiry = t.expiry
                if expiry and expiry < current_time:
                    to_delete_tokens.append(k)
            for k in to_delete_tokens:
                del self._data.reset_tokens[k]

    async def get_session_context(
        self, session_key: bytes, host: str | None = None
    ) -> SessionContext | None:
        # Need to acquire session lock for potential write (host binding)
        async with self._lock:
            sess_key_b64 = _bytes_to_str(session_key)
            if sess_key_b64 not in self._data.sessions:
                return None

            s = self._data.sessions[sess_key_b64]

            # Handle host binding
            if host is not None:
                if s.host is None:
                    s.host = host
                    # Mark for save
                    await self._save()
                elif s.host != host:
                    return None

            # Build session object
            session_obj = Session(
                key=_str_to_bytes(sess_key_b64),  # type: ignore[arg-type]
                user_uuid=UUID(s.user),
                credential_uuid=UUID(s.credential),
                host=s.host,
                ip=s.ip,
                user_agent=s.user_agent,
                renewed=s.renewed,  # Already datetime
            )

            # Get user
            user_key = s.user
            if user_key not in self._data.users:
                return None
            u = self._data.users[user_key]
            user_obj = User(
                uuid=UUID(user_key),
                display_name=u.display_name,
                role_uuid=UUID(u.role),
                created_at=u.created_at,
                last_seen=u.last_seen,
                visits=u.visits,
            )

            # Get role
            role_uuid = u.role
            if role_uuid not in self._data.roles:
                return None
            r = self._data.roles[role_uuid]
            role_obj = Role(
                uuid=UUID(role_uuid),
                org_uuid=UUID(r.org),
                display_name=r.display_name,
                permissions=list(r.permissions),
            )

            # Get org
            org_uuid = r.org
            if org_uuid not in self._data.orgs:
                return None
            o = self._data.orgs[org_uuid]
            org_obj = Org(
                uuid=UUID(org_uuid),  # Use the key directly
                display_name=o.display_name,
                permissions=[],  # Could populate from permissions if needed
            )

            # Get credential (optional)
            cred_uuid = s.credential
            credential_obj = None
            if cred_uuid in self._data.credentials:
                c = self._data.credentials[cred_uuid]
                credential_obj = Credential(
                    uuid=UUID(cred_uuid),  # Use the key directly
                    credential_id=c.credential_id,  # Already bytes
                    user_uuid=UUID(c.user),
                    aaguid=UUID(c.aaguid),
                    public_key=c.public_key,  # Already bytes
                    sign_count=c.sign_count,
                    created_at=c.created_at,  # Already datetime
                    last_used=c.last_used,
                    last_verified=c.last_verified,
                )

            # Collect permissions for the role
            permissions = []
            for pid in role_obj.permissions:
                if pid in self._data.permissions:
                    p = self._data.permissions[pid]
                    permissions.append(Permission(id=pid, display_name=p.display_name))

            # Filter effective permissions: only include permissions that the org can grant
            effective_permissions = [
                p for p in permissions if p.id in org_obj.permissions
            ]

            # Filter effective permissions: only include permissions that the org can grant
            effective_permissions = [
                p for p in permissions if p.id in org_obj.permissions
            ]

            return SessionContext(
                session=session_obj,
                user=user_obj,
                org=org_obj,
                role=role_obj,
                credential=credential_obj,
                permissions=effective_permissions if effective_permissions else None,
            )
