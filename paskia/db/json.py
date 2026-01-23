"""
JSON database implementation for WebAuthn passkey authentication.

This module provides a JSON file-based database layer that maintains all data
in memory and persists changes to disk as JSONL. Uses object keys by UUID
instead of lists for efficient lookups.

All public data types are msgspec Structs for efficient serialization.
Database methods are synchronous since all data is in memory.
A background task periodically flushes queued changes to disk.
"""

import asyncio
import logging
import os
import threading
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import base64url
import jsondiff
import msgspec

from paskia.config import SESSION_LIFETIME

DB_PATH_DEFAULT = "paskia.jsonl"

# Flush changes to disk every N seconds
FLUSH_INTERVAL = 5
# Cleanup expired items every N seconds (cheap when nothing to remove)
CLEANUP_INTERVAL = 1


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
    expiry: datetime

    def metadata(self) -> dict:
        """Return session metadata for backwards compatibility."""
        return {
            "ip": self.ip,
            "user_agent": self.user_agent,
            "expiry": self.expiry.isoformat(),
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
_background_task: asyncio.Task | None = None

_logger = logging.getLogger(__name__)


def get_db() -> "DB":
    """Get the global database instance."""
    if _db is None:
        raise RuntimeError("Database not initialized. Call init() first.")
    return _db


async def _background_loop():
    """Background task that periodically flushes changes and cleans up."""
    # Run cleanup immediately on startup to clear old expired items
    if _db is not None:
        _db.cleanup()
        _db.flush()

    last_cleanup = datetime.now(timezone.utc)

    while True:
        try:
            await asyncio.sleep(FLUSH_INTERVAL)
            if _db is not None:
                # Flush pending changes to disk
                _db.flush()

                # Run cleanup less frequently
                now = datetime.now(timezone.utc)
                if (now - last_cleanup).total_seconds() >= CLEANUP_INTERVAL:
                    _db.cleanup()
                    _db.flush()  # Flush cleanup changes
                    last_cleanup = now
        except asyncio.CancelledError:
            # Final flush before exit
            if _db is not None:
                _db.flush()
            break
        except Exception:
            _logger.exception("Error in database background loop")


async def start_background():
    """Start the background flush/cleanup task."""
    global _background_task
    if _background_task is None:
        _background_task = asyncio.create_task(_background_loop())


async def stop_background():
    """Stop the background task and flush any pending changes."""
    global _background_task
    if _background_task:
        _background_task.cancel()
        try:
            await _background_task
        except asyncio.CancelledError:
            pass
        _background_task = None


# Aliases for backwards compatibility
start_cleanup = start_background
stop_cleanup = stop_background


async def init(*args, **kwargs):
    """Initialize the global database instance and start background task."""
    global _db
    db_path = os.environ.get("PASKIA_DB", DB_PATH_DEFAULT)
    # Remove any prefix (for compatibility with SQL-style URIs)
    if db_path.startswith("json:"):
        db_path = db_path[5:]
    _db = DB(db_path)
    _db.load()
    await start_background()


class DB:
    """JSON-based database implementation.

    All methods are synchronous since data is maintained in memory.
    Changes are queued and periodically flushed to disk by a background task.
    Each change records the actor (user UUID or system identifier).

    Thread-safety: Uses a lock for concurrent access to the data structure.

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
        self._pending_changes: deque[_ChangeRecord] = deque()
        self._lock = threading.RLock()  # Reentrant for nested calls
        self._current_actor: str = "system"  # Default actor for changes

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

    def load(self) -> None:
        """Load data from disk by applying change log.

        Replays all changes from JSONL file using plain dicts (to handle
        schema evolution), then validates the final state against msgspec
        structs which become the working copy with proper datetime types.
        """
        with self._lock:
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

    def _queue_change(self) -> None:
        """Queue a change record for later flush. Must hold lock."""
        if self._data is None:
            return
        # Convert current struct to builtins for diffing (datetime->str, bytes->base64)
        current_builtins = msgspec.to_builtins(self._data)

        # Calculate diff between previous and current state (marshal=True for JSON-serializable keys)
        diff = jsondiff.diff(self._previous_builtins, current_builtins, marshal=True)

        # Only queue if there are changes
        if diff:
            change_record = _ChangeRecord(
                ts=datetime.now(timezone.utc),
                actor=self._current_actor,
                diff=diff,
            )
            self._pending_changes.append(change_record)
            # Update previous builtins for next diff
            self._previous_builtins = current_builtins

    def flush(self) -> None:
        """Write all pending changes to disk."""
        with self._lock:
            if not self._pending_changes:
                return

            # Collect all pending changes
            changes_to_write = list(self._pending_changes)
            self._pending_changes.clear()

        # Write outside the lock to avoid blocking other operations
        try:
            # Build lines to append
            lines = []
            for change in changes_to_write:
                data = _json_encoder.encode(change)
                lines.append(data.decode("utf-8"))

            # Read existing content and append
            existing_content = ""
            if self.db_path.exists():
                existing_content = self.db_path.read_text("utf-8")

            new_content = existing_content + "\n".join(lines) + "\n"

            # Write atomically via temp file
            tmp_path = self.db_path.with_suffix(".tmp")
            tmp_path.write_text(new_content, "utf-8")
            tmp_path.replace(self.db_path)
        except OSError:
            _logger.exception("Failed to flush database changes")
            # Re-queue the changes on failure
            with self._lock:
                for change in reversed(changes_to_write):
                    self._pending_changes.appendleft(change)

    @contextmanager
    def session(self, actor: str = "system"):
        """Context manager for atomic operations with change queued on exit."""
        with self._lock:
            old_actor = self._current_actor
            self._current_actor = actor
            try:
                yield
                self._queue_change()
            finally:
                self._current_actor = old_actor

    # -------------------------------------------------------------------------
    # Internal helpers (caller must hold lock)
    # -------------------------------------------------------------------------

    def _build_user(self, user_uuid: str) -> User:
        """Build a User object from internal storage. Caller must hold lock."""
        u = self._data.users[user_uuid]
        return User(
            uuid=UUID(user_uuid),
            display_name=u.display_name,
            role_uuid=UUID(u.role),
            created_at=u.created_at,
            last_seen=u.last_seen,
            visits=u.visits,
        )

    def _build_role(self, role_uuid: str) -> Role:
        """Build a Role object from internal storage. Caller must hold lock."""
        r = self._data.roles[role_uuid]
        return Role(
            uuid=UUID(role_uuid),
            org_uuid=UUID(r.org),
            display_name=r.display_name,
            permissions=list(r.permissions),
        )

    def _build_org(self, org_uuid: str, include_roles: bool = False) -> Org:
        """Build an Org object from internal storage. Caller must hold lock."""
        o = self._data.orgs[org_uuid]
        # Get permissions this org can grant
        perm_ids = [
            pid for pid, p in self._data.permissions.items() if org_uuid in p.orgs
        ]
        org = Org(
            uuid=UUID(org_uuid),
            display_name=o.display_name,
            permissions=perm_ids,
        )
        if include_roles:
            org.roles = [
                self._build_role(role_uuid)
                for role_uuid, r in self._data.roles.items()
                if r.org == org_uuid
            ]
        return org

    def _build_credential(self, cred_uuid: str) -> Credential:
        """Build a Credential object from internal storage. Caller must hold lock."""
        c = self._data.credentials[cred_uuid]
        return Credential(
            uuid=UUID(cred_uuid),
            credential_id=c.credential_id,
            user_uuid=UUID(c.user),
            aaguid=UUID(c.aaguid),
            public_key=c.public_key,
            sign_count=c.sign_count,
            created_at=c.created_at,
            last_used=c.last_used,
            last_verified=c.last_verified,
        )

    def _build_session(self, sess_key_b64: str) -> Session:
        """Build a Session object from internal storage. Caller must hold lock."""
        s = self._data.sessions[sess_key_b64]
        return Session(
            key=_str_to_bytes(sess_key_b64),  # type: ignore[arg-type]
            user_uuid=UUID(s.user),
            credential_uuid=UUID(s.credential),
            host=s.host,
            ip=s.ip,
            user_agent=s.user_agent,
            expiry=s.expiry,
        )

    # -------------------------------------------------------------------------
    # User operations
    # -------------------------------------------------------------------------

    def get_user_by_uuid(self, user_uuid: UUID) -> User:
        with self._lock:
            key = str(user_uuid)
            if key not in self._data.users:
                raise ValueError("User not found")
            return self._build_user(key)

    def create_user(self, user: User, actor: str = "system") -> None:
        with self.session(actor):
            key = str(user.uuid)
            self._data.users[key] = _UserData(
                display_name=user.display_name,
                role=str(user.role_uuid),
                created_at=user.created_at or datetime.now(timezone.utc),
                last_seen=user.last_seen,
                visits=user.visits,
            )

    def update_user_display_name(
        self, user_uuid: UUID, display_name: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
            key = str(user_uuid)
            if key not in self._data.users:
                raise ValueError("User not found")
            self._data.users[key].display_name = display_name

    # -------------------------------------------------------------------------
    # Role operations
    # -------------------------------------------------------------------------

    def create_role(self, role: Role, actor: str = "system") -> None:
        with self.session(actor):
            key = str(role.uuid)
            self._data.roles[key] = _RoleData(
                org=str(role.org_uuid),
                display_name=role.display_name,
                permissions={p: True for p in role.permissions}
                if role.permissions
                else {},
            )

    def update_role(self, role: Role, actor: str = "system") -> None:
        with self.session(actor):
            key = str(role.uuid)
            if key not in self._data.roles:
                raise ValueError("Role not found")
            self._data.roles[key].display_name = role.display_name
            self._data.roles[key].permissions = (
                {p: True for p in role.permissions} if role.permissions else {}
            )

    def delete_role(self, role_uuid: UUID, actor: str = "system") -> None:
        with self.session(actor):
            key = str(role_uuid)
            # Check for users with this role
            for u in self._data.users.values():
                if u.role == key:
                    raise ValueError("Cannot delete role with assigned users")
            if key in self._data.roles:
                del self._data.roles[key]

    def get_role(self, role_uuid: UUID) -> Role:
        with self._lock:
            key = str(role_uuid)
            if key not in self._data.roles:
                raise ValueError("Role not found")
            return self._build_role(key)

    # -------------------------------------------------------------------------
    # Credential operations
    # -------------------------------------------------------------------------

    def create_credential(self, credential: Credential, actor: str = "system") -> None:
        with self.session(actor):
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

    def get_credential_by_id(self, credential_id: bytes) -> Credential:
        with self._lock:
            for key, c in self._data.credentials.items():
                if c.credential_id == credential_id:
                    return self._build_credential(key)
            raise ValueError("Credential not found")

    def get_credentials_by_user_uuid(self, user_uuid: UUID) -> list[bytes]:
        with self._lock:
            user_key = str(user_uuid)
            result: list[bytes] = []
            for c in self._data.credentials.values():
                if c.user == user_key:
                    cred_id = c.credential_id
                    if cred_id is not None:
                        result.append(cred_id)
            return result

    def update_credential(self, credential: Credential, actor: str = "system") -> None:
        with self.session(actor):
            for key, c in self._data.credentials.items():
                if c.credential_id == credential.credential_id:
                    c.sign_count = credential.sign_count
                    c.created_at = credential.created_at
                    c.last_used = credential.last_used
                    c.last_verified = credential.last_verified
                    return
            raise ValueError("Credential not found")

    def delete_credential(self, uuid: UUID, user_uuid: UUID, actor: str = "system") -> None:
        with self.session(actor):
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

    def create_session(
        self,
        user_uuid: UUID,
        key: bytes,
        credential_uuid: UUID,
        host: str,
        ip: str,
        user_agent: str,
        expiry: datetime,
        actor: str = "system",
    ) -> None:
        with self.session(actor):
            key_b64 = _bytes_to_str(key)
            self._data.sessions[key_b64] = _SessionData(
                user=str(user_uuid),
                credential=str(credential_uuid),
                host=host,
                ip=ip,
                user_agent=user_agent,
                expiry=expiry,
            )

    def get_session(self, key: bytes) -> Session | None:
        with self._lock:
            key_b64 = _bytes_to_str(key)
            if key_b64 not in self._data.sessions:
                return None
            return self._build_session(key_b64)

    def delete_session(self, key: bytes, actor: str = "system") -> None:
        with self.session(actor):
            key_b64 = _bytes_to_str(key)
            if key_b64 in self._data.sessions:
                del self._data.sessions[key_b64]

    def update_session(
        self,
        key: bytes,
        *,
        ip: str,
        user_agent: str,
        expiry: datetime,
        actor: str = "system",
    ) -> Session | None:
        with self.session(actor):
            key_b64 = _bytes_to_str(key)
            if key_b64 not in self._data.sessions:
                return None
            s = self._data.sessions[key_b64]
            s.ip = ip
            s.user_agent = user_agent
            s.expiry = expiry
            return self._build_session(key_b64)

    def set_session_host(self, key: bytes, host: str, actor: str = "system") -> None:
        with self.session(actor):
            key_b64 = _bytes_to_str(key)
            if key_b64 in self._data.sessions:
                s = self._data.sessions[key_b64]
                if s.host is None:
                    s.host = host

    def list_sessions_for_user(self, user_uuid: UUID) -> list[Session]:
        with self._lock:
            user_key = str(user_uuid)
            sessions = []
            for key_b64, s in self._data.sessions.items():
                if s.user == user_key:
                    key_bytes = _str_to_bytes(key_b64)
                    if key_bytes and key_bytes.startswith(b"sess"):
                        sessions.append(self._build_session(key_b64))
            # Sort by expiry desc (most recent expiry first)
            sessions.sort(key=lambda x: x.expiry, reverse=True)
            return sessions

    def delete_sessions_for_user(self, user_uuid: UUID, actor: str = "system") -> None:
        with self.session(actor):
            user_key = str(user_uuid)
            to_delete = [
                k for k, s in self._data.sessions.items() if s.user == user_key
            ]
            for k in to_delete:
                del self._data.sessions[k]

    # -------------------------------------------------------------------------
    # Reset token operations
    # -------------------------------------------------------------------------

    def create_reset_token(
        self,
        user_uuid: UUID,
        key: bytes,
        expiry: datetime,
        token_type: str,
        actor: str = "system",
    ) -> None:
        with self.session(actor):
            key_b64 = _bytes_to_str(key)
            self._data.reset_tokens[key_b64] = _ResetTokenData(
                user=str(user_uuid),
                expiry=expiry,
                token_type=token_type,
            )

    def get_reset_token(self, key: bytes) -> ResetToken | None:
        with self._lock:
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

    def delete_reset_token(self, key: bytes, actor: str = "system") -> None:
        with self.session(actor):
            key_b64 = _bytes_to_str(key)
            if key_b64 in self._data.reset_tokens:
                del self._data.reset_tokens[key_b64]

    # -------------------------------------------------------------------------
    # Organization operations
    # -------------------------------------------------------------------------

    def create_organization(self, org: Org, actor: str = "system") -> None:
        with self.session(actor):
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

    def get_organization(self, org_id: str) -> Org:
        with self._lock:
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            return self._build_org(org_id, include_roles=True)

    def list_organizations(self) -> list[Org]:
        with self._lock:
            return [
                self._build_org(org_uuid, include_roles=True)
                for org_uuid in self._data.orgs
            ]

    def update_organization(self, org: Org, actor: str = "system") -> None:
        with self.session(actor):
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

    def delete_organization(self, org_uuid: UUID, actor: str = "system") -> None:
        with self.session(actor):
            key = str(org_uuid)
            if key in self._data.orgs:
                del self._data.orgs[key]
            # Cascade delete roles belonging to this org
            to_delete = [k for k, r in self._data.roles.items() if r.org == key]
            for k in to_delete:
                del self._data.roles[k]

    def add_user_to_organization(
        self, user_uuid: UUID, org_id: str, role: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
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

    def transfer_user_to_organization(
        self, user_uuid: UUID, new_org_id: str, new_role: str | None = None
    ) -> None:
        raise ValueError("Users cannot be transferred to a different organization")

    def get_user_organization(self, user_uuid: UUID) -> tuple[Org, str]:
        with self._lock:
            user_key = str(user_uuid)
            if user_key not in self._data.users:
                raise ValueError("User not found")
            role_uuid = self._data.users[user_key].role
            if role_uuid not in self._data.roles:
                raise ValueError("Role not found")
            r = self._data.roles[role_uuid]
            if r.org not in self._data.orgs:
                raise ValueError("Organization not found")
            return self._build_org(r.org), r.display_name

    def get_organization_users(self, org_id: str) -> list[tuple[User, str]]:
        with self._lock:
            # Get all roles for this org
            org_role_uuids = {
                role_uuid for role_uuid, r in self._data.roles.items() if r.org == org_id
            }
            return [
                (self._build_user(user_uuid), self._data.roles[u.role].display_name)
                for user_uuid, u in self._data.users.items()
                if u.role in org_role_uuids
            ]

    def get_roles_by_organization(self, org_id: str) -> list[Role]:
        with self._lock:
            return [
                self._build_role(role_uuid)
                for role_uuid, r in self._data.roles.items()
                if r.org == org_id
            ]

    def get_user_role_in_organization(
        self, user_uuid: UUID, org_id: str
    ) -> str | None:
        with self._lock:
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

    def update_user_role_in_organization(
        self, user_uuid: UUID, new_role: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
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

    def create_permission(self, permission: Permission, actor: str = "system") -> None:
        with self.session(actor):
            self._data.permissions[permission.id] = _PermissionData(
                display_name=permission.display_name,
                orgs={},  # Will be populated when orgs are allowed to grant this permission
            )

    def get_permission(self, permission_id: str) -> Permission:
        with self._lock:
            if permission_id not in self._data.permissions:
                raise ValueError("Permission not found")
            p = self._data.permissions[permission_id]
            return Permission(id=permission_id, display_name=p.display_name)

    def list_permissions(self) -> list[Permission]:
        with self._lock:
            return [
                Permission(id=pid, display_name=p.display_name)
                for pid, p in self._data.permissions.items()
            ]

    def update_permission(self, permission: Permission, actor: str = "system") -> None:
        with self.session(actor):
            if permission.id not in self._data.permissions:
                raise ValueError("Permission not found")
            self._data.permissions[permission.id].display_name = permission.display_name

    def delete_permission(self, permission_id: str, actor: str = "system") -> None:
        with self.session(actor):
            if permission_id in self._data.permissions:
                del self._data.permissions[permission_id]
            # Remove from roles (permissions is a dict)
            for r in self._data.roles.values():
                if permission_id in r.permissions:
                    del r.permissions[permission_id]

    def rename_permission(
        self, old_id: str, new_id: str, display_name: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
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

    def add_permission_to_organization(
        self, org_id: str, permission_id: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            if permission_id not in self._data.permissions:
                raise ValueError("Permission not found")
            self._data.permissions[permission_id].orgs[org_id] = True

    def remove_permission_from_organization(
        self, org_id: str, permission_id: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
            if permission_id in self._data.permissions:
                orgs = self._data.permissions[permission_id].orgs
                if org_id in orgs:
                    del orgs[org_id]

    def get_organization_permissions(self, org_id: str) -> list[Permission]:
        with self._lock:
            if org_id not in self._data.orgs:
                raise ValueError("Organization not found")
            permissions = []
            for pid, p in self._data.permissions.items():
                if org_id in p.orgs:
                    permissions.append(Permission(id=pid, display_name=p.display_name))
            return permissions

    def get_permission_organizations(self, permission_id: str) -> list[Org]:
        with self._lock:
            if permission_id not in self._data.permissions:
                return []
            org_ids = self._data.permissions[permission_id].orgs
            return [
                self._build_org(org_id)
                for org_id in org_ids
                if org_id in self._data.orgs
            ]

    # -------------------------------------------------------------------------
    # Role-permission operations
    # -------------------------------------------------------------------------

    def add_permission_to_role(
        self, role_uuid: UUID, permission_id: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
            key = str(role_uuid)
            if key not in self._data.roles:
                raise ValueError("Role not found")
            if permission_id not in self._data.permissions:
                raise ValueError("Permission not found")
            self._data.roles[key].permissions[permission_id] = True

    def remove_permission_from_role(
        self, role_uuid: UUID, permission_id: str, actor: str = "system"
    ) -> None:
        with self.session(actor):
            key = str(role_uuid)
            if key in self._data.roles:
                if permission_id in self._data.roles[key].permissions:
                    del self._data.roles[key].permissions[permission_id]

    def get_role_permissions(self, role_uuid: UUID) -> list[Permission]:
        with self._lock:
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

    def get_permission_roles(self, permission_id: str) -> list[Role]:
        with self._lock:
            return [
                self._build_role(role_uuid)
                for role_uuid, r in self._data.roles.items()
                if permission_id in r.permissions
            ]

    # -------------------------------------------------------------------------
    # Combined operations
    # -------------------------------------------------------------------------

    def login(self, user_uuid: UUID, credential: Credential, actor: str = "system") -> None:
        with self.session(actor):
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

    def create_user_and_credential(
        self, user: User, credential: Credential, actor: str = "system"
    ) -> None:
        with self.session(actor):
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

    def create_credential_session(
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
        actor: str = "system",
    ) -> None:
        with self.session(actor):
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

            # New session - compute expiry from credential.last_used
            sess_key_b64 = _bytes_to_str(session_key)
            self._data.sessions[sess_key_b64] = _SessionData(
                user=user_key,
                credential=cred_key,
                host=host,
                ip=ip,
                user_agent=user_agent,
                expiry=credential.last_used + SESSION_LIFETIME,
            )

            # Login side-effects
            if user_key in self._data.users:
                self._data.users[user_key].last_seen = credential.last_used
                self._data.users[user_key].visits = (
                    self._data.users[user_key].visits + 1
                )

    def cleanup(self) -> None:
        """Remove expired sessions and reset tokens."""
        with self.session("expiry"):
            current_time = datetime.now(timezone.utc)

            # Clean expired sessions
            to_delete_sessions = []
            for k, s in self._data.sessions.items():
                if s.expiry < current_time:
                    to_delete_sessions.append(k)
            for k in to_delete_sessions:
                del self._data.sessions[k]

            # Clean expired reset tokens
            to_delete_tokens = []
            for k, t in self._data.reset_tokens.items():
                if t.expiry < current_time:
                    to_delete_tokens.append(k)
            for k in to_delete_tokens:
                del self._data.reset_tokens[k]

    def get_session_context(
        self, session_key: bytes, host: str | None = None
    ) -> SessionContext | None:
        """Get full authentication context from a session key.

        This is the primary method for validating sessions and getting all
        associated user/org/role/credential data in a single call.
        """
        with self._lock:
            sess_key_b64 = _bytes_to_str(session_key)
            if sess_key_b64 not in self._data.sessions:
                return None

            s = self._data.sessions[sess_key_b64]

            # Handle host binding
            if host is not None:
                if s.host is None:
                    s.host = host
                    self._queue_change()  # Queue change for host binding
                elif s.host != host:
                    return None

            # Validate user exists
            user_key = s.user
            if user_key not in self._data.users:
                return None

            # Validate role exists
            role_uuid = self._data.users[user_key].role
            if role_uuid not in self._data.roles:
                return None

            # Validate org exists
            org_uuid = self._data.roles[role_uuid].org
            if org_uuid not in self._data.orgs:
                return None

            # Build objects using helpers
            session_obj = self._build_session(sess_key_b64)
            user_obj = self._build_user(user_key)
            role_obj = self._build_role(role_uuid)
            org_obj = self._build_org(org_uuid)

            # Get credential (optional)
            cred_uuid = s.credential
            credential_obj = (
                self._build_credential(cred_uuid)
                if cred_uuid in self._data.credentials
                else None
            )

            # Effective permissions: role permissions that the org can grant
            effective_permissions = [
                Permission(id=pid, display_name=self._data.permissions[pid].display_name)
                for pid in role_obj.permissions
                if pid in self._data.permissions and pid in org_obj.permissions
            ]

            return SessionContext(
                session=session_obj,
                user=user_obj,
                org=org_obj,
                role=role_obj,
                credential=credential_obj,
                permissions=effective_permissions or None,
            )
