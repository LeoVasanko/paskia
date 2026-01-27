"""
Database for WebAuthn passkey authentication.

Read operations: Access _db._data directly, use build_* helpers to get public structs.
Context lookup: get_session_context() returns full SessionContext with effective permissions.
Write operations: Functions that validate and commit, or raise ValueError.
"""

import hashlib
import json
import logging
import os
import secrets
import sys
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import msgspec

from paskia.db.jsonl import (
    DB_PATH_DEFAULT,
    _ChangeRecord,
    compute_diff,
    create_change_record,
    load_jsonl,
)
from paskia.db.structs import (
    Credential,
    DatabaseData,
    Org,
    Permission,
    ResetToken,
    Role,
    Session,
    SessionContext,
    User,
)
from paskia.util.passphrase import is_well_formed as _is_passphrase

_logger = logging.getLogger(__name__)

# msgspec encoder/decoder
_json_encoder = msgspec.json.Encoder()
_json_decoder = msgspec.json.Decoder(DatabaseData)


class DB:
    """In-memory database with JSONL persistence.

    Access data directly via _data for reads.
    Use transaction() context manager for writes.
    """

    def __init__(self, db_path: str = DB_PATH_DEFAULT):
        self.db_path = Path(db_path)
        self._data = DatabaseData(
            permissions={},
            orgs={},
            roles={},
            users={},
            credentials={},
            sessions={},
            reset_tokens={},
        )
        self._previous_builtins: dict[str, Any] = {}
        self._pending_changes: deque[_ChangeRecord] = deque()
        self._current_action: str = "system"
        self._current_user: str | None = None

    async def load(self, db_path: str | None = None) -> None:
        """Load data from JSONL change log.

        If file doesn't exist or is empty, keeps the initialized empty structure and
        sets _previous_builtins to {} for creating a new database.
        """
        if db_path is not None:
            self.db_path = Path(db_path)
        try:
            data_dict = await load_jsonl(self.db_path)
            if data_dict:  # Only decode if we have data
                self._data = _json_decoder.decode(_json_encoder.encode(data_dict))
                # Track the JSONL file state directly - this is what we diff against
                self._previous_builtins = data_dict
            # If data_dict is empty, keep initialized _data and _previous_builtins = {}
        except ValueError:
            if self.db_path.exists():
                raise  # File exists but failed to load - re-raise
            # File doesn't exist: keep initialized _data, _previous_builtins stays {}

    def _queue_change(self) -> None:
        current = msgspec.to_builtins(self._data)
        diff = compute_diff(self._previous_builtins, current)
        if diff:
            self._pending_changes.append(
                create_change_record(self._current_action, diff, self._current_user)
            )
            self._previous_builtins = current
            # Log the change with user display name if available
            user_display = None
            if self._current_user:
                try:
                    user_uuid = UUID(self._current_user)
                    if user_uuid in self._data.users:
                        user_display = self._data.users[user_uuid].display_name
                except (ValueError, KeyError):
                    user_display = self._current_user

            diff_json = json.dumps(diff, default=str)
            if user_display:
                print(
                    f"{self._current_action} by {user_display}: {diff_json}",
                    file=sys.stderr,
                )
            else:
                print(f"{self._current_action}: {diff_json}", file=sys.stderr)

    @contextmanager
    def transaction(
        self,
        action: str,
        ctx: SessionContext | None = None,
        *,
        user: str | None = None,
    ):
        """Wrap writes in transaction. Queues change on successful exit.

        Args:
            action: Describes the operation (e.g., "Created user", "Login")
            ctx: Session context of user performing the action (None for system operations)
            user: User UUID string (alternative to ctx when full context unavailable)
        """
        old_action = self._current_action
        old_user = self._current_user
        self._current_action = action
        # Prefer ctx.user.uuid if ctx provided, otherwise use user param
        self._current_user = str(ctx.user.uuid) if ctx else user
        try:
            yield
            self._queue_change()
        finally:
            self._current_action = old_action
            self._current_user = old_user


# Global instance, always available (empty until init() loads data)
_db = DB()


async def init(*args, **kwargs):
    """Load database from JSONL file."""
    db_path = os.environ.get("PASKIA_DB", DB_PATH_DEFAULT)
    if db_path.startswith("json:"):
        db_path = db_path[5:]
    await _db.load(db_path)


# -------------------------------------------------------------------------
# Builders: Convert internal _*Data to public structs
# -------------------------------------------------------------------------


def build_permission(uuid: UUID) -> Permission:
    perm = _db._data.permissions[uuid]
    perm.uuid = uuid
    return perm


def build_user(uuid: UUID) -> User:
    user = _db._data.users[uuid]
    user.uuid = uuid
    return user


def build_role(uuid: UUID) -> Role:
    r = _db._data.roles[uuid]
    r.uuid = uuid
    return r


def build_org(uuid: UUID, include_roles: bool = False) -> Org:
    o = _db._data.orgs[uuid]
    o.uuid = uuid
    o.permissions = {pid for pid, p in _db._data.permissions.items() if uuid in p.orgs}
    if include_roles:
        o.roles = [
            build_role(rid) for rid, r in _db._data.roles.items() if r.org == uuid
        ]
    return o


def build_credential(uuid: UUID) -> Credential:
    cred = _db._data.credentials[uuid]
    cred.uuid = uuid
    return cred


def build_session(key: str) -> Session:
    s = _db._data.sessions[key]
    s.key = key
    return s


def build_reset_token(key: bytes) -> ResetToken:
    t = _db._data.reset_tokens[key]
    t.key = key
    return t


# -------------------------------------------------------------------------
# Read/lookup functions
# -------------------------------------------------------------------------


def get_permission(permission_id: str | UUID) -> Permission | None:
    """Get permission by UUID or scope.

    For backwards compatibility, this accepts either:
    - A UUID string (the primary key)
    - A scope string (searches for matching scope)
    """
    # First try as UUID key
    if isinstance(permission_id, UUID):
        if permission_id in _db._data.permissions:
            return build_permission(permission_id)
    else:
        try:
            uuid = UUID(permission_id)
            if uuid in _db._data.permissions:
                return build_permission(uuid)
        except ValueError:
            pass
    # Fall back to scope search
    for uuid, p in _db._data.permissions.items():
        if p.scope == str(permission_id):
            return build_permission(uuid)
    return None


def get_permission_by_scope(scope: str) -> Permission | None:
    """Get permission by scope identifier."""
    for uuid, p in _db._data.permissions.items():
        if p.scope == scope:
            return build_permission(uuid)
    return None


def list_permissions() -> list[Permission]:
    """List all permissions."""
    return [build_permission(uuid) for uuid in _db._data.permissions]


def get_permission_organizations(scope: str) -> list[Org]:
    """Get organizations that can grant a permission scope."""
    for p in _db._data.permissions.values():
        if p.scope == scope:
            return [build_org(org_uuid) for org_uuid in p.orgs]
    return []


def get_organization(uuid: str | UUID) -> Org | None:
    """Get organization by UUID."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    return build_org(uuid, include_roles=True) if uuid in _db._data.orgs else None


def list_organizations() -> list[Org]:
    """List all organizations."""
    return [build_org(uuid, include_roles=True) for uuid in _db._data.orgs]


def get_organization_users(org_uuid: str | UUID) -> list[tuple[User, str]]:
    """Get all users in an organization with their role names."""
    if isinstance(org_uuid, str):
        org_uuid = UUID(org_uuid)
    role_map = {
        rid: r.display_name for rid, r in _db._data.roles.items() if r.org == org_uuid
    }
    return [
        (build_user(uid), role_map[u.role])
        for uid, u in _db._data.users.items()
        if u.role in role_map
    ]


def get_role(uuid: str | UUID) -> Role | None:
    """Get role by UUID."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    return build_role(uuid) if uuid in _db._data.roles else None


def get_roles_by_organization(org_uuid: str | UUID) -> list[Role]:
    """Get all roles in an organization."""
    if isinstance(org_uuid, str):
        org_uuid = UUID(org_uuid)
    return [build_role(rid) for rid, r in _db._data.roles.items() if r.org == org_uuid]


def get_user_by_uuid(uuid: str | UUID) -> User | None:
    """Get user by UUID."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    return build_user(uuid) if uuid in _db._data.users else None


def get_user_organization(user_uuid: str | UUID) -> tuple[Org, str]:
    """Get the organization a user belongs to and their role name.

    Raises ValueError if user not found.
    """
    if isinstance(user_uuid, str):
        user_uuid = UUID(user_uuid)
    if user_uuid not in _db._data.users:
        raise ValueError(f"User {user_uuid} not found")
    role_uuid = _db._data.users[user_uuid].role
    if role_uuid not in _db._data.roles:
        raise ValueError(f"Role {role_uuid} not found")
    role_data = _db._data.roles[role_uuid]
    org_uuid = role_data.org
    return build_org(org_uuid, include_roles=True), role_data.display_name


def get_credential_by_id(credential_id: bytes) -> Credential | None:
    """Get credential by credential_id (the authenticator's ID)."""
    for uuid, c in _db._data.credentials.items():
        if c.credential_id == credential_id:
            return build_credential(uuid)
    return None


def get_credentials_by_user_uuid(user_uuid: str | UUID) -> list[Credential]:
    """Get all credentials for a user."""
    if isinstance(user_uuid, str):
        user_uuid = UUID(user_uuid)
    return [
        build_credential(cid)
        for cid, c in _db._data.credentials.items()
        if c.user == user_uuid
    ]


def get_session(key: str) -> Session | None:
    """Get session by key."""
    if key not in _db._data.sessions:
        return None
    s = _db._data.sessions[key]
    if s.expiry < datetime.now(timezone.utc):
        return None
    return build_session(key)


def list_sessions_for_user(user_uuid: str | UUID) -> list[Session]:
    """Get all active sessions for a user."""
    if isinstance(user_uuid, str):
        user_uuid = UUID(user_uuid)
    now = datetime.now(timezone.utc)
    return [
        build_session(key)
        for key, s in _db._data.sessions.items()
        if s.user == user_uuid and s.expiry >= now
    ]


def _reset_key(passphrase: str) -> bytes:
    """Hash a passphrase to bytes for reset token storage."""
    if not _is_passphrase(passphrase):
        raise ValueError(
            "Trying to reset with a session token in place of a passphrase"
            if len(passphrase) == 16
            else "Invalid passphrase format"
        )
    return hashlib.sha512(passphrase.encode()).digest()[:9]


def get_reset_token(passphrase: str) -> ResetToken | None:
    """Get reset token by passphrase."""
    key = _reset_key(passphrase)
    if key not in _db._data.reset_tokens:
        return None
    t = _db._data.reset_tokens[key]
    if t.expiry < datetime.now(timezone.utc):
        return None
    return build_reset_token(key)


# -------------------------------------------------------------------------
# Context lookup
# -------------------------------------------------------------------------


def get_session_context(
    session_key: str, host: str | None = None
) -> SessionContext | None:
    """Get full session context with effective permissions.

    Args:
        session_key: The session key string
        host: Optional host for binding/validation and domain-scoped permissions

    Returns:
        SessionContext if valid, None if session not found, expired, or host mismatch
    """
    from paskia.util.hostutil import normalize_host

    if session_key not in _db._data.sessions:
        return None

    s = _db._data.sessions[session_key]
    if s.expiry < datetime.now(timezone.utc):
        return None

    # Handle host binding
    if host is not None:
        if s.host is None:
            # Bind session to this host
            with _db.transaction("host_binding"):
                s.host = host
        elif s.host != host:
            # Session bound to different host
            return None

    # Validate user exists
    if s.user not in _db._data.users:
        return None

    # Validate role exists
    role_uuid = _db._data.users[s.user].role
    if role_uuid not in _db._data.roles:
        return None

    # Validate org exists
    org_uuid = _db._data.roles[role_uuid].org
    if org_uuid not in _db._data.orgs:
        return None

    session = build_session(session_key)
    user = build_user(s.user)
    role = build_role(role_uuid)
    org = build_org(org_uuid)

    # Credential must exist (sessions are cascade-deleted when credential is deleted)
    if s.credential not in _db._data.credentials:
        return None
    credential = build_credential(s.credential)

    # Effective permissions: role's permissions that the org can grant
    # Also filter by domain if host is provided
    org_perm_uuids = org.permissions  # set[UUID] computed by build_org
    normalized_host = normalize_host(host)
    host_without_port = normalized_host.rsplit(":", 1)[0] if normalized_host else None

    effective_perms = []
    for perm_uuid in role.permission_set:
        if perm_uuid not in org_perm_uuids:
            continue
        if perm_uuid not in _db._data.permissions:
            continue
        p = _db._data.permissions[perm_uuid]
        # Check domain restriction
        if p.domain is not None and p.domain != host_without_port:
            continue
        effective_perms.append(build_permission(perm_uuid))

    return SessionContext(
        session=session,
        user=user,
        org=org,
        role=role,
        credential=credential,
        permissions=effective_perms,
    )


# -------------------------------------------------------------------------
# Write operations (validate, modify, commit or raise ValueError)
# -------------------------------------------------------------------------


def create_permission(perm: Permission, *, ctx: SessionContext | None = None) -> None:
    """Create a new permission."""
    if perm.uuid in _db._data.permissions:
        raise ValueError(f"Permission {perm.uuid} already exists")
    with _db.transaction("Created permission", ctx):
        _db._data.permissions[perm.uuid] = perm


def update_permission(perm: Permission, *, ctx: SessionContext | None = None) -> None:
    """Update a permission's scope, display_name, and domain."""
    if perm.uuid not in _db._data.permissions:
        raise ValueError(f"Permission {perm.uuid} not found")
    with _db.transaction("Updated permission", ctx):
        _db._data.permissions[perm.uuid].scope = perm.scope
        _db._data.permissions[perm.uuid].display_name = perm.display_name
        _db._data.permissions[perm.uuid].domain = perm.domain


def rename_permission(
    old_scope: str,
    new_scope: str,
    display_name: str,
    domain: str | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Rename a permission's scope. The UUID remains the same.

    Since roles reference permissions by UUID, no role updates are needed.
    Note: Scopes do not need to be unique (same scope with different domains is valid).
    """
    # Find permission by old scope
    key = None
    for pid, p in _db._data.permissions.items():
        if p.scope == old_scope:
            key = pid
            break
    if not key:
        raise ValueError(f"Permission with scope '{old_scope}' not found")

    with _db.transaction("Renamed permission", ctx):
        # Update the permission
        _db._data.permissions[key].scope = new_scope
        _db._data.permissions[key].display_name = display_name
        _db._data.permissions[key].domain = domain


def delete_permission(uuid: str | UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete a permission and remove it from all roles."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.permissions:
        raise ValueError(f"Permission {uuid} not found")
    with _db.transaction("Deleted permission", ctx):
        # Remove this permission from all roles
        for role in _db._data.roles.values():
            role.permissions.pop(uuid, None)
        del _db._data.permissions[uuid]


def create_organization(org: Org, *, ctx: SessionContext | None = None) -> None:
    """Create a new organization with an Administration role.

    Automatically creates an 'Administration' role with auth:org:admin permission.
    """
    if org.uuid in _db._data.orgs:
        raise ValueError(f"Organization {org.uuid} already exists")
    with _db.transaction("Created organization", ctx):
        _db._data.orgs[org.uuid] = Org(
            display_name=org.display_name, created_at=datetime.now(timezone.utc)
        )
        # Create Administration role with org admin permission
        import uuid7

        admin_role_uuid = uuid7.create()
        # Find the auth:org:admin permission UUID
        org_admin_perm_uuid = None
        for pid, p in _db._data.permissions.items():
            if p.scope == "auth:org:admin":
                org_admin_perm_uuid = pid
                break
        role_permissions = {org_admin_perm_uuid: True} if org_admin_perm_uuid else {}
        admin_role = Role(
            org=org.uuid,
            display_name="Administration",
            permissions=role_permissions,
        )
        admin_role.uuid = admin_role_uuid
        _db._data.roles[admin_role_uuid] = admin_role


def update_organization_name(
    uuid: str | UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update organization display name."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.orgs:
        raise ValueError(f"Organization {uuid} not found")
    with _db.transaction("Renamed organization", ctx):
        _db._data.orgs[uuid].display_name = display_name


def delete_organization(uuid: str | UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete organization and all its roles/users."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.orgs:
        raise ValueError(f"Organization {uuid} not found")
    with _db.transaction("Deleted organization", ctx):
        # Remove org from all permissions
        for p in _db._data.permissions.values():
            p.orgs.pop(uuid, None)
        # Delete roles in this org
        role_uuids = [rid for rid, r in _db._data.roles.items() if r.org == uuid]
        for rid in role_uuids:
            del _db._data.roles[rid]
        # Delete users with those roles
        user_uuids = [uid for uid, u in _db._data.users.items() if u.role in role_uuids]
        for uid in user_uuids:
            del _db._data.users[uid]
        del _db._data.orgs[uuid]


def add_permission_to_organization(
    org_uuid: str | UUID,
    permission_id: str | UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Grant a permission to an organization by UUID."""
    if isinstance(org_uuid, str):
        org_uuid = UUID(org_uuid)
    if org_uuid not in _db._data.orgs:
        raise ValueError(f"Organization {org_uuid} not found")

    # Convert permission_id to UUID
    if isinstance(permission_id, str):
        try:
            permission_uuid = UUID(permission_id)
        except ValueError:
            # It's a scope - look up the UUID (backwards compat)
            for pid, p in _db._data.permissions.items():
                if p.scope == permission_id:
                    permission_uuid = pid
                    break
            else:
                raise ValueError(f"Permission {permission_id} not found")
    else:
        permission_uuid = permission_id

    if permission_uuid not in _db._data.permissions:
        raise ValueError(f"Permission {permission_uuid} not found")

    with _db.transaction("Granted org permission", ctx):
        _db._data.permissions[permission_uuid].orgs[org_uuid] = True


def remove_permission_from_organization(
    org_uuid: str | UUID,
    permission_id: str | UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Remove a permission from an organization by UUID."""
    if isinstance(org_uuid, str):
        org_uuid = UUID(org_uuid)
    if org_uuid not in _db._data.orgs:
        raise ValueError(f"Organization {org_uuid} not found")

    # Convert permission_id to UUID
    if isinstance(permission_id, str):
        try:
            permission_uuid = UUID(permission_id)
        except ValueError:
            # It's a scope - look up the UUID (backwards compat)
            for pid, p in _db._data.permissions.items():
                if p.scope == permission_id:
                    permission_uuid = pid
                    break
            else:
                return  # Permission not found, silently return
    else:
        permission_uuid = permission_id

    if permission_uuid not in _db._data.permissions:
        return  # Permission not found, silently return

    with _db.transaction("Revoked org permission", ctx):
        _db._data.permissions[permission_uuid].orgs.pop(org_uuid, None)


def create_role(role: Role, *, ctx: SessionContext | None = None) -> None:
    """Create a new role."""
    if role.uuid in _db._data.roles:
        raise ValueError(f"Role {role.uuid} already exists")
    if role.org not in _db._data.orgs:
        raise ValueError(f"Organization {role.org} not found")
    with _db.transaction("Created role", ctx):
        _db._data.roles[role.uuid] = role


def update_role_name(
    uuid: str | UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update role display name."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.roles:
        raise ValueError(f"Role {uuid} not found")
    with _db.transaction("Renamed role", ctx):
        _db._data.roles[uuid].display_name = display_name


def add_permission_to_role(
    role_uuid: str | UUID,
    permission_uuid: str | UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Add permission to role by UUID."""
    if isinstance(role_uuid, str):
        role_uuid = UUID(role_uuid)
    if isinstance(permission_uuid, str):
        permission_uuid = UUID(permission_uuid)
    if role_uuid not in _db._data.roles:
        raise ValueError(f"Role {role_uuid} not found")
    if permission_uuid not in _db._data.permissions:
        raise ValueError(f"Permission {permission_uuid} not found")
    with _db.transaction("Granted role permission", ctx):
        _db._data.roles[role_uuid].permissions[permission_uuid] = True


def remove_permission_from_role(
    role_uuid: str | UUID,
    permission_uuid: str | UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Remove permission from role by UUID."""
    if isinstance(role_uuid, str):
        role_uuid = UUID(role_uuid)
    if isinstance(permission_uuid, str):
        permission_uuid = UUID(permission_uuid)
    if role_uuid not in _db._data.roles:
        raise ValueError(f"Role {role_uuid} not found")
    with _db.transaction("Revoked role permission", ctx):
        _db._data.roles[role_uuid].permissions.pop(permission_uuid, None)


def delete_role(uuid: str | UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete a role."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.roles:
        raise ValueError(f"Role {uuid} not found")
    # Check no users have this role
    if any(u.role == uuid for u in _db._data.users.values()):
        raise ValueError(f"Cannot delete role {uuid}: users still assigned")
    with _db.transaction("Deleted role", ctx):
        del _db._data.roles[uuid]


def create_user(new_user: User, *, ctx: SessionContext | None = None) -> None:
    """Create a new user."""
    if new_user.uuid in _db._data.users:
        raise ValueError(f"User {new_user.uuid} already exists")
    if new_user.role not in _db._data.roles:
        raise ValueError(f"Role {new_user.role} not found")
    with _db.transaction("Created user", ctx):
        _db._data.users[new_user.uuid] = new_user


def update_user_display_name(
    uuid: str | UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user display name.

    For self-service (user updating own name), ctx can be None and user is derived from uuid.
    For admin operations, ctx should be provided.
    """
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.users:
        raise ValueError(f"User {uuid} not found")
    # For self-service, derive user from the uuid being modified
    user_str = str(uuid) if not ctx else None
    with _db.transaction("Renamed user", ctx, user=user_str):
        _db._data.users[uuid].display_name = display_name


def update_user_role(
    uuid: str | UUID,
    role_uuid: str | UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user's role."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if isinstance(role_uuid, str):
        role_uuid = UUID(role_uuid)
    if uuid not in _db._data.users:
        raise ValueError(f"User {uuid} not found")
    if role_uuid not in _db._data.roles:
        raise ValueError(f"Role {role_uuid} not found")
    with _db.transaction("Changed user role", ctx):
        _db._data.users[uuid].role = role_uuid


def update_user_role_in_organization(
    user_uuid: str | UUID,
    role_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user's role by role name within their current organization."""
    if isinstance(user_uuid, str):
        user_uuid = UUID(user_uuid)
    if user_uuid not in _db._data.users:
        raise ValueError(f"User {user_uuid} not found")
    current_role_uuid = _db._data.users[user_uuid].role
    if current_role_uuid not in _db._data.roles:
        raise ValueError("Current role not found")
    org_uuid = _db._data.roles[current_role_uuid].org
    # Find role by name in the same org
    new_role_uuid = None
    for rid, r in _db._data.roles.items():
        if r.org == org_uuid and r.display_name == role_name:
            new_role_uuid = rid
            break
    if new_role_uuid is None:
        raise ValueError(f"Role '{role_name}' not found in organization")
    with _db.transaction("Changed user role", ctx):
        _db._data.users[user_uuid].role = new_role_uuid


def delete_user(uuid: str | UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete user and their credentials/sessions."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.users:
        raise ValueError(f"User {uuid} not found")
    with _db.transaction("Deleted user", ctx):
        # Delete credentials
        cred_uuids = [cid for cid, c in _db._data.credentials.items() if c.user == uuid]
        for cid in cred_uuids:
            del _db._data.credentials[cid]
        # Delete sessions
        sess_keys = [k for k, s in _db._data.sessions.items() if s.user == uuid]
        for k in sess_keys:
            del _db._data.sessions[k]
        # Delete reset tokens
        token_keys = [k for k, t in _db._data.reset_tokens.items() if t.user == uuid]
        for k in token_keys:
            del _db._data.reset_tokens[k]
        del _db._data.users[uuid]


def create_credential(cred: Credential, *, ctx: SessionContext | None = None) -> None:
    """Create a new credential."""
    if cred.uuid in _db._data.credentials:
        raise ValueError(f"Credential {cred.uuid} already exists")
    if cred.user not in _db._data.users:
        raise ValueError(f"User {cred.user} not found")
    with _db.transaction("Added credential", ctx):
        _db._data.credentials[cred.uuid] = cred


def update_credential_sign_count(
    uuid: str | UUID,
    sign_count: int,
    last_used: datetime | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update credential sign count and last_used."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.credentials:
        raise ValueError(f"Credential {uuid} not found")
    with _db.transaction("Updated credential", ctx):
        _db._data.credentials[uuid].sign_count = sign_count
        if last_used:
            _db._data.credentials[uuid].last_used = last_used


def delete_credential(
    uuid: str | UUID,
    user_uuid: str | UUID | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Delete a credential and all sessions using it.

    If user_uuid is provided, validates that the credential belongs to that user.
    """
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db._data.credentials:
        raise ValueError(f"Credential {uuid} not found")
    if user_uuid is not None:
        if isinstance(user_uuid, str):
            user_uuid = UUID(user_uuid)
        cred_user = _db._data.credentials[uuid].user
        if cred_user != user_uuid:
            raise ValueError(f"Credential {uuid} does not belong to user {user_uuid}")
    with _db.transaction("Deleted credential", ctx):
        # Delete all sessions using this credential
        keys = [k for k, s in _db._data.sessions.items() if s.credential == uuid]
        for k in keys:
            del _db._data.sessions[k]
        del _db._data.credentials[uuid]


def create_session(
    key: str,
    user_uuid: UUID,
    credential_uuid: UUID,
    host: str | None,
    ip: str | None,
    user_agent: str | None,
    expiry: datetime,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Create a new session."""
    if key in _db._data.sessions:
        raise ValueError("Session already exists")
    if user_uuid not in _db._data.users:
        raise ValueError(f"User {user_uuid} not found")
    if credential_uuid not in _db._data.credentials:
        raise ValueError(f"Credential {credential_uuid} not found")
    with _db.transaction("Created session", ctx):
        _db._data.sessions[key] = Session(
            user=user_uuid,
            credential=credential_uuid,
            host=host,
            ip=ip,
            user_agent=user_agent,
            expiry=expiry,
        )


def update_session(
    key: str,
    host: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    expiry: datetime | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update session metadata."""
    if key not in _db._data.sessions:
        raise ValueError("Session not found")
    with _db.transaction("Updated session", ctx):
        s = _db._data.sessions[key]
        if host is not None:
            s.host = host
        if ip is not None:
            s.ip = ip
        if user_agent is not None:
            s.user_agent = user_agent
        if expiry is not None:
            s.expiry = expiry


def set_session_host(key: str, host: str, *, ctx: SessionContext | None = None) -> None:
    """Set the host for a session (first-time binding)."""
    update_session(key, host=host, ctx=ctx)


def delete_session(key: str, *, ctx: SessionContext | None = None) -> None:
    """Delete a session.

    For logout (user deleting own session), ctx can be None and user is derived from session.
    For admin operations, ctx should be provided.
    """
    if key not in _db._data.sessions:
        raise ValueError("Session not found")
    # For self-service logout, derive user from the session being deleted
    user_str = str(_db._data.sessions[key].user) if not ctx else None
    with _db.transaction("Deleted session", ctx, user=user_str):
        del _db._data.sessions[key]


def delete_sessions_for_user(
    user_uuid: str | UUID, *, ctx: SessionContext | None = None
) -> None:
    """Delete all sessions for a user.

    For logout-all (user deleting own sessions), ctx can be None and user is derived from user_uuid.
    For admin operations, ctx should be provided.
    """
    if isinstance(user_uuid, str):
        user_uuid = UUID(user_uuid)
    # For self-service, derive user from the user_uuid param
    user_str = str(user_uuid) if not ctx else None
    with _db.transaction("Deleted user sessions", ctx, user=user_str):
        keys = [k for k, s in _db._data.sessions.items() if s.user == user_uuid]
        for k in keys:
            del _db._data.sessions[k]


def create_reset_token(
    passphrase: str,
    user_uuid: UUID,
    expiry: datetime,
    token_type: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Create a reset token from a passphrase.

    For self-service (user creating own recovery link), ctx can be None and user is derived from user_uuid.
    For admin operations, ctx should be provided.
    """
    key = _reset_key(passphrase)
    if key in _db._data.reset_tokens:
        raise ValueError("Reset token already exists")
    if user_uuid not in _db._data.users:
        raise ValueError(f"User {user_uuid} not found")
    # For self-service, derive user from the user_uuid param
    user_str = str(user_uuid) if not ctx else None
    with _db.transaction("Created reset token", ctx, user=user_str):
        _db._data.reset_tokens[key] = ResetToken(
            user=user_uuid, expiry=expiry, token_type=token_type
        )


def delete_reset_token(key: bytes, *, ctx: SessionContext | None = None) -> None:
    """Delete a reset token."""
    if key not in _db._data.reset_tokens:
        raise ValueError("Reset token not found")
    with _db.transaction("Deleted reset token", ctx):
        del _db._data.reset_tokens[key]


# -------------------------------------------------------------------------
# Cleanup (called by background task)
# -------------------------------------------------------------------------


def cleanup_expired() -> int:
    """Remove expired sessions and reset tokens. Returns count removed."""
    now = datetime.now(timezone.utc)
    count = 0
    with _db.transaction("Cleaned up expired"):
        expired_sessions = [k for k, s in _db._data.sessions.items() if s.expiry < now]
        for k in expired_sessions:
            del _db._data.sessions[k]
            count += 1
        expired_tokens = [
            k for k, t in _db._data.reset_tokens.items() if t.expiry < now
        ]
        for k in expired_tokens:
            del _db._data.reset_tokens[k]
            count += 1
    return count


# -------------------------------------------------------------------------
# Composite operations (used by app code)
# -------------------------------------------------------------------------


def _create_token() -> str:
    """Generate a 16-character URL-safe session token."""
    return secrets.token_urlsafe(12)


def login(
    user_uuid: str | UUID,
    credential: Credential,
    host: str | None,
    ip: str | None,
    user_agent: str | None,
    expiry: datetime,
) -> str:
    """Update user/credential on login and create session in a single transaction.

    Updates:
    - user.last_seen, user.visits
    - credential.sign_count, credential.last_used
    Creates:
    - new session

    Returns the generated session token.
    """
    if isinstance(user_uuid, str):
        user_uuid = UUID(user_uuid)
    now = datetime.now(timezone.utc)
    if user_uuid not in _db._data.users:
        raise ValueError(f"User {user_uuid} not found")
    if credential.uuid not in _db._data.credentials:
        raise ValueError(f"Credential {credential.uuid} not found")

    session_key = _create_token()
    user_str = str(user_uuid)
    with _db.transaction("User logged in", user=user_str):
        # Update user
        _db._data.users[user_uuid].last_seen = now
        _db._data.users[user_uuid].visits += 1
        # Update credential
        _db._data.credentials[credential.uuid].sign_count = credential.sign_count
        _db._data.credentials[credential.uuid].last_used = now
        # Create session
        _db._data.sessions[session_key] = Session(
            user=user_uuid,
            credential=credential.uuid,
            host=host,
            ip=ip,
            user_agent=user_agent,
            expiry=expiry,
        )
    return session_key


def create_credential_session(
    user_uuid: UUID,
    credential: Credential,
    host: str | None,
    ip: str | None,
    user_agent: str | None,
    display_name: str | None = None,
    reset_key: bytes | None = None,
) -> str:
    """Create a credential and session together, optionally consuming a reset token.

    Used during registration to atomically:
    1. Update user display_name if provided
    2. Create the credential
    3. Create the session
    4. Delete the reset token if provided

    Returns the generated session token.
    """
    from paskia.config import SESSION_LIFETIME

    now = datetime.now(timezone.utc)
    expiry = now + SESSION_LIFETIME
    session_key = _create_token()

    if user_uuid not in _db._data.users:
        raise ValueError(f"User {user_uuid} not found")

    user_str = str(user_uuid)
    with _db.transaction("Registered credential", user=user_str):
        # Update display name if provided
        if display_name:
            _db._data.users[user_uuid].display_name = display_name

        # Create credential
        _db._data.credentials[credential.uuid] = credential

        # Create session
        _db._data.sessions[session_key] = Session(
            user=user_uuid,
            credential=credential.uuid,
            host=host,
            ip=ip,
            user_agent=user_agent,
            expiry=expiry,
        )

        # Delete reset token if provided
        if reset_key:
            if reset_key in _db._data.reset_tokens:
                del _db._data.reset_tokens[reset_key]
    return session_key


# -------------------------------------------------------------------------
# Bootstrap (single transaction for initial system setup)
# -------------------------------------------------------------------------


def bootstrap(
    org_name: str = "Organization",
    admin_name: str = "Admin",
    reset_passphrase: str | None = None,
    reset_expiry: datetime | None = None,
) -> dict:
    """Bootstrap the entire system in a single transaction.

    Creates:
    - auth:admin permission (Master Admin)
    - auth:org:admin permission (Org Admin)
    - Organization with Administration role
    - Admin user with Administration role
    - Reset token for admin registration

    This is the only way to create a new database file (besides migrate).
    All data is created atomically - if any step fails, nothing is written.

    Args:
        org_name: Display name for the organization (default: "Organization")
        admin_name: Display name for the admin user (default: "Admin")
        reset_passphrase: Passphrase for the reset token (generated if not provided)
        reset_expiry: Expiry datetime for the reset token (default: 14 days)

    Returns:
        dict with keys: perm_admin, perm_org_admin, org, role, user, reset_passphrase
    """
    import uuid7

    from paskia.authsession import reset_expires
    from paskia.util.passphrase import generate as generate_passphrase

    # Check if system is already bootstrapped
    for p in _db._data.permissions.values():
        if p.scope == "auth:admin":
            raise ValueError(
                "System already bootstrapped (auth:admin permission exists)"
            )

    # Generate UUIDs upfront
    perm_admin_uuid = uuid7.create()
    perm_org_admin_uuid = uuid7.create()
    org_uuid = uuid7.create()
    role_uuid = uuid7.create()
    user_uuid = uuid7.create()

    # Generate reset token components
    if reset_passphrase is None:
        reset_passphrase = generate_passphrase()
    if reset_expiry is None:
        reset_expiry = reset_expires()
    reset_key = _reset_key(reset_passphrase)

    now = datetime.now(timezone.utc)

    with _db.transaction("bootstrap"):
        # Create auth:admin permission
        perm_admin = Permission(
            scope="auth:admin",
            display_name="Master Admin",
            orgs={org_uuid: True},  # Grant to org
        )
        perm_admin.uuid = perm_admin_uuid
        _db._data.permissions[perm_admin_uuid] = perm_admin

        # Create auth:org:admin permission
        perm_org_admin = Permission(
            scope="auth:org:admin",
            display_name="Org Admin",
            orgs={org_uuid: True},  # Grant to org
        )
        perm_org_admin.uuid = perm_org_admin_uuid
        _db._data.permissions[perm_org_admin_uuid] = perm_org_admin

        # Create organization
        new_org = Org(
            display_name=org_name,
            created_at=now,
        )
        new_org.uuid = org_uuid
        _db._data.orgs[org_uuid] = new_org

        # Create Administration role with both permissions
        admin_role = Role(
            org=org_uuid,
            display_name="Administration",
            permissions={perm_admin_uuid: True, perm_org_admin_uuid: True},
        )
        admin_role.uuid = role_uuid
        _db._data.roles[role_uuid] = admin_role

        # Create admin user
        admin_user = User(
            display_name=admin_name,
            role=role_uuid,
            created_at=now,
            last_seen=None,
            visits=0,
        )
        admin_user.uuid = user_uuid
        _db._data.users[user_uuid] = admin_user

        # Create reset token
        _db._data.reset_tokens[reset_key] = ResetToken(
            user=user_uuid,
            expiry=reset_expiry,
            token_type="admin bootstrap",
        )

    # Return info about what was created (for logging by caller)
    return {
        "perm_admin": build_permission(perm_admin_uuid),
        "perm_org_admin": build_permission(perm_org_admin_uuid),
        "org": build_org(org_uuid),
        "role": build_role(role_uuid),
        "user": build_user(user_uuid),
        "reset_passphrase": reset_passphrase,
    }
