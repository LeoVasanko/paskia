"""
Database for WebAuthn passkey authentication.

Read operations: Access _db directly, use build_* helpers to get public structs.
Context lookup: get_session_context() returns full SessionContext with effective permissions.
Write operations: Functions that validate and commit, or raise ValueError.
"""

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from uuid import UUID

import uuid7

from paskia.config import SESSION_LIFETIME
from paskia.db.jsonl import (
    DB_PATH_DEFAULT,
    JsonlStore,
)
from paskia.db.structs import (
    DB,
    Credential,
    Org,
    Permission,
    ResetToken,
    Role,
    Session,
    SessionContext,
    User,
)
from paskia.util.hostutil import normalize_host
from paskia.util.passphrase import generate as generate_passphrase
from paskia.util.passphrase import is_well_formed as _is_passphrase

_logger = logging.getLogger(__name__)

# Global database instance (empty until init() loads data)
_db = DB()
_store = JsonlStore(_db)
_db._store = _store


async def init(*args, **kwargs):
    """Load database from JSONL file."""
    global _db
    db_path = os.environ.get("PASKIA_DB", DB_PATH_DEFAULT)
    if db_path.startswith("json:"):
        db_path = db_path[5:]
    await _store.load(db_path)
    _db = _store.db


# -------------------------------------------------------------------------
# Read/lookup functions
# -------------------------------------------------------------------------


def get_user_organization(user_uuid: UUID) -> tuple[Org, str]:
    """Get the organization a user belongs to and their role name.

    Raises ValueError if user not found.

    Call sites:
    - Get user's organization when updating user role (admin.py:493)
    - Get user's organization for user credential listing (admin.py:530)
    - Get user's organization for user details API (admin.py:579)
    - Get user's organization for updating user display name (admin.py:721)
    - Get user's organization for deleting user credential (admin.py:754)
    - Get user's organization for deleting user session (admin.py:783)
    """
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    role_uuid = _db.users[user_uuid].role
    if role_uuid not in _db.roles:
        raise ValueError(f"Role {role_uuid} not found")
    role_data = _db.roles[role_uuid]
    org_uuid = role_data.org
    return _db.orgs[org_uuid], role_data.display_name


def get_organization_users(org_uuid: UUID) -> list[tuple[User, str]]:
    """Get all users in an organization with their role names.

    Returns list of (User, role_display_name) tuples.
    """
    role_map = {
        rid: r.display_name for rid, r in _db.roles.items() if r.org == org_uuid
    }
    return [(u, role_map[u.role]) for u in _db.users.values() if u.role in role_map]


def get_user_credential_ids(user_uuid: UUID) -> list[bytes]:
    """Get credential IDs for a user (for WebAuthn exclude lists).

    Returns empty list if user has no credentials.
    """
    return [c.credential_id for c in _db.credentials.values() if c.user == user_uuid]


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
    """Get reset token by passphrase.

    Call sites:
    - Get reset token to validate it (authsession.py:34)
    """
    key = _reset_key(passphrase)
    return _db.reset_tokens.get(key)


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

    Call sites:
    - Example usage in docstring (db/__init__.py:16)
    - Get session context from auth token (util/permutil.py:43)
    """

    if session_key not in _db.sessions:
        return None

    s = _db.sessions[session_key]
    if s.expiry < datetime.now(timezone.utc):
        return None

    # Handle host binding
    if host is not None:
        if s.host is None:
            # Bind session to this host
            with _db.transaction("bind_session_host"):
                s.host = host
        elif s.host != host:
            # Session bound to different host
            return None

    # Validate user exists
    if s.user not in _db.users:
        return None

    # Validate role exists
    role_uuid = _db.users[s.user].role
    if role_uuid not in _db.roles:
        return None

    # Validate org exists
    org_uuid = _db.roles[role_uuid].org
    if org_uuid not in _db.orgs:
        return None

    session = _db.sessions[session_key]
    user = _db.users[s.user]
    role = _db.roles[role_uuid]
    org = _db.orgs[org_uuid]

    # Credential must exist (sessions are cascade-deleted when credential is deleted)
    if s.credential not in _db.credentials:
        return None
    credential = _db.credentials[s.credential]

    # Effective permissions: role's permissions that the org can grant
    # Also filter by domain if host is provided
    org_perm_uuids = {pid for pid, p in _db.permissions.items() if org_uuid in p.orgs}
    normalized_host = normalize_host(host)
    host_without_port = normalized_host.rsplit(":", 1)[0] if normalized_host else None

    effective_perms = []
    for perm_uuid in role.permission_set:
        if perm_uuid not in org_perm_uuids:
            continue
        if perm_uuid not in _db.permissions:
            continue
        p = _db.permissions[perm_uuid]
        # Check domain restriction
        if p.domain is not None and p.domain != host_without_port:
            continue
        effective_perms.append(_db.permissions[perm_uuid])

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
    if perm.uuid in _db.permissions:
        raise ValueError(f"Permission {perm.uuid} already exists")
    with _db.transaction("admin:create_permission", ctx):
        _db.permissions[perm.uuid] = perm


def update_permission(
    uuid: UUID,
    scope: str,
    display_name: str,
    domain: str | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update a permission's scope, display_name, and domain.

    Only these fields can be modified; created_at and other metadata remain immutable.
    """
    if uuid not in _db.permissions:
        raise ValueError(f"Permission {uuid} not found")
    with _db.transaction("admin:update_permission", ctx):
        _db.permissions[uuid].scope = scope
        _db.permissions[uuid].display_name = display_name
        _db.permissions[uuid].domain = domain


def delete_permission(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete a permission and remove it from all roles."""
    if uuid not in _db.permissions:
        raise ValueError(f"Permission {uuid} not found")
    with _db.transaction("admin:delete_permission", ctx):
        # Remove this permission from all roles
        for role in _db.roles.values():
            role.permissions.pop(uuid, None)
        del _db.permissions[uuid]


def create_org(org: Org, *, ctx: SessionContext | None = None) -> None:
    """Create a new organization with an Administration role.

    Automatically creates an 'Administration' role with auth:org:admin permission.
    """
    if org.uuid in _db.orgs:
        raise ValueError(f"Organization {org.uuid} already exists")
    with _db.transaction("admin:create_org", ctx):
        new_org = Org(
            display_name=org.display_name, created_at=datetime.now(timezone.utc)
        )
        _db.orgs[org.uuid] = new_org
        new_org.uuid = org.uuid
        # Create Administration role with org admin permission

        admin_role_uuid = uuid7.create()
        # Find the auth:org:admin permission UUID
        org_admin_perm_uuid = None
        for pid, p in _db.permissions.items():
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
        _db.roles[admin_role_uuid] = admin_role


def update_org_name(
    uuid: UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update organization display name."""
    if uuid not in _db.orgs:
        raise ValueError(f"Organization {uuid} not found")
    with _db.transaction("admin:update_org_name", ctx):
        _db.orgs[uuid].display_name = display_name


def delete_org(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete organization and all its roles/users."""
    if uuid not in _db.orgs:
        raise ValueError(f"Organization {uuid} not found")
    with _db.transaction("admin:delete_org", ctx):
        # Remove org from all permissions
        for p in _db.permissions.values():
            p.orgs.pop(uuid, None)
        # Delete roles in this org
        role_uuids = [rid for rid, r in _db.roles.items() if r.org == uuid]
        for rid in role_uuids:
            del _db.roles[rid]
        # Delete users with those roles
        user_uuids = [uid for uid, u in _db.users.items() if u.role in role_uuids]
        for uid in user_uuids:
            del _db.users[uid]
        del _db.orgs[uuid]


def add_permission_to_org(
    org_uuid: UUID,
    permission_uuid: UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Grant a permission to an organization by UUID."""
    if org_uuid not in _db.orgs:
        raise ValueError(f"Organization {org_uuid} not found")

    if permission_uuid not in _db.permissions:
        raise ValueError(f"Permission {permission_uuid} not found")

    with _db.transaction("admin:add_permission_to_org", ctx):
        _db.permissions[permission_uuid].orgs[org_uuid] = True


def remove_permission_from_org(
    org_uuid: UUID,
    permission_uuid: UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Remove a permission from an organization by UUID."""
    if org_uuid not in _db.orgs:
        raise ValueError(f"Organization {org_uuid} not found")

    if permission_uuid not in _db.permissions:
        return  # Permission not found, silently return

    with _db.transaction("admin:remove_permission_from_org", ctx):
        _db.permissions[permission_uuid].orgs.pop(org_uuid, None)


def create_role(role: Role, *, ctx: SessionContext | None = None) -> None:
    """Create a new role."""
    if role.uuid in _db.roles:
        raise ValueError(f"Role {role.uuid} already exists")
    if role.org not in _db.orgs:
        raise ValueError(f"Organization {role.org} not found")
    with _db.transaction("admin:create_role", ctx):
        _db.roles[role.uuid] = role


def update_role_name(
    uuid: UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update role display name."""
    if uuid not in _db.roles:
        raise ValueError(f"Role {uuid} not found")
    with _db.transaction("admin:update_role_name", ctx):
        _db.roles[uuid].display_name = display_name


def add_permission_to_role(
    role_uuid: UUID,
    permission_uuid: UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Add permission to role by UUID."""
    if role_uuid not in _db.roles:
        raise ValueError(f"Role {role_uuid} not found")
    if permission_uuid not in _db.permissions:
        raise ValueError(f"Permission {permission_uuid} not found")
    with _db.transaction("admin:add_permission_to_role", ctx):
        _db.roles[role_uuid].permissions[permission_uuid] = True


def remove_permission_from_role(
    role_uuid: UUID,
    permission_uuid: UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Remove permission from role by UUID."""
    if role_uuid not in _db.roles:
        raise ValueError(f"Role {role_uuid} not found")
    with _db.transaction("admin:remove_permission_from_role", ctx):
        _db.roles[role_uuid].permissions.pop(permission_uuid, None)


def delete_role(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete a role."""
    if uuid not in _db.roles:
        raise ValueError(f"Role {uuid} not found")
    # Check no users have this role
    if any(u.role == uuid for u in _db.users.values()):
        raise ValueError(f"Cannot delete role {uuid}: users still assigned")
    with _db.transaction("admin:delete_role", ctx):
        del _db.roles[uuid]


def create_user(new_user: User, *, ctx: SessionContext | None = None) -> None:
    """Create a new user."""
    if new_user.uuid in _db.users:
        raise ValueError(f"User {new_user.uuid} already exists")
    if new_user.role not in _db.roles:
        raise ValueError(f"Role {new_user.role} not found")
    with _db.transaction("admin:create_user", ctx):
        _db.users[new_user.uuid] = new_user


def update_user_display_name(
    uuid: UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user display name.

    The acting user should be logged via ctx.
    For self-service (user updating own name), pass user's ctx.
    For admin operations, pass admin's ctx.
    """
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    with _db.transaction("update_user_display_name", ctx):
        _db.users[uuid].display_name = display_name


def update_user_role(
    uuid: UUID,
    role_uuid: UUID,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user's role."""
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    if role_uuid not in _db.roles:
        raise ValueError(f"Role {role_uuid} not found")
    with _db.transaction("admin:update_user_role", ctx):
        _db.users[uuid].role = role_uuid


def update_user_role_in_organization(
    user_uuid: UUID,
    role_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user's role by role name within their current organization."""
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    current_role_uuid = _db.users[user_uuid].role
    if current_role_uuid not in _db.roles:
        raise ValueError("Current role not found")
    org_uuid = _db.roles[current_role_uuid].org
    # Find role by name in the same org
    new_role_uuid = None
    for rid, r in _db.roles.items():
        if r.org == org_uuid and r.display_name == role_name:
            new_role_uuid = rid
            break
    if new_role_uuid is None:
        raise ValueError(f"Role '{role_name}' not found in organization")
    with _db.transaction("admin:update_user_role", ctx):
        _db.users[user_uuid].role = new_role_uuid


def delete_user(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete user and their credentials/sessions."""
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    with _db.transaction("admin:delete_user", ctx):
        # Delete credentials
        cred_uuids = [cid for cid, c in _db.credentials.items() if c.user == uuid]
        for cid in cred_uuids:
            del _db.credentials[cid]
        # Delete sessions
        sess_keys = [k for k, s in _db.sessions.items() if s.user == uuid]
        for k in sess_keys:
            del _db.sessions[k]
        # Delete reset tokens
        token_keys = [k for k, t in _db.reset_tokens.items() if t.user == uuid]
        for k in token_keys:
            del _db.reset_tokens[k]
        del _db.users[uuid]


def create_credential(cred: Credential, *, ctx: SessionContext | None = None) -> None:
    """Create a new credential."""
    if cred.uuid in _db.credentials:
        raise ValueError(f"Credential {cred.uuid} already exists")
    if cred.user not in _db.users:
        raise ValueError(f"User {cred.user} not found")
    with _db.transaction("create_credential", ctx):
        _db.credentials[cred.uuid] = cred


def update_credential_sign_count(
    uuid: UUID,
    sign_count: int,
    last_used: datetime | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update credential sign count and last_used."""
    if uuid not in _db.credentials:
        raise ValueError(f"Credential {uuid} not found")
    with _db.transaction("update_credential_sign_count", ctx):
        _db.credentials[uuid].sign_count = sign_count
        if last_used:
            _db.credentials[uuid].last_used = last_used


def delete_credential(
    uuid: UUID,
    user_uuid: UUID | None = None,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Delete a credential and all sessions using it.

    If user_uuid is provided, validates that the credential belongs to that user.
    """
    if uuid not in _db.credentials:
        raise ValueError(f"Credential {uuid} not found")
    if user_uuid is not None:
        cred_user = _db.credentials[uuid].user
        if cred_user != user_uuid:
            raise ValueError(f"Credential {uuid} does not belong to user {user_uuid}")
    with _db.transaction("delete_credential", ctx):
        # Delete all sessions using this credential
        keys = [k for k, s in _db.sessions.items() if s.credential == uuid]
        for k in keys:
            del _db.sessions[k]
        del _db.credentials[uuid]


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
    if key in _db.sessions:
        raise ValueError("Session already exists")
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    if credential_uuid not in _db.credentials:
        raise ValueError(f"Credential {credential_uuid} not found")
    with _db.transaction("create_session", ctx):
        _db.sessions[key] = Session(
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
    if key not in _db.sessions:
        raise ValueError("Session not found")
    with _db.transaction("update_session", ctx):
        s = _db.sessions[key]
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

    The acting user should be logged via ctx.
    For user logout, pass ctx of the user's session.
    For admin terminating a session, pass admin's ctx.
    """
    if key not in _db.sessions:
        raise ValueError("Session not found")
    with _db.transaction("delete_session", ctx):
        del _db.sessions[key]


def delete_sessions_for_user(
    user_uuid: UUID, *, ctx: SessionContext | None = None
) -> None:
    """Delete all sessions for a user.

    The acting user should be logged via ctx.
    For user logout-all, pass ctx of the user's session.
    For admin bulk termination, pass admin's ctx.
    """
    with _db.transaction("admin:delete_sessions_for_user", ctx):
        keys = [k for k, s in _db.sessions.items() if s.user == user_uuid]
        for k in keys:
            del _db.sessions[k]


def create_reset_token(
    passphrase: str,
    user_uuid: UUID,
    expiry: datetime,
    token_type: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Create a reset token from a passphrase.

    The acting user should be logged via ctx.
    For self-service (user creating own recovery link), pass user's ctx.
    For admin operations, pass admin's ctx.
    For system operations (bootstrap), pass neither to log no user.
    """
    key = _reset_key(passphrase)
    if key in _db.reset_tokens:
        raise ValueError("Reset token already exists")
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    with _db.transaction("create_reset_token", ctx):
        _db.reset_tokens[key] = ResetToken(
            user=user_uuid, expiry=expiry, token_type=token_type
        )


def delete_reset_token(key: bytes, *, ctx: SessionContext | None = None) -> None:
    """Delete a reset token."""
    if key not in _db.reset_tokens:
        raise ValueError("Reset token not found")
    with _db.transaction("delete_reset_token", ctx):
        del _db.reset_tokens[key]


# -------------------------------------------------------------------------
# Cleanup (called by background task)
# -------------------------------------------------------------------------


def cleanup_expired() -> int:
    """Remove expired sessions and reset tokens. Returns count removed."""
    now = datetime.now(timezone.utc)
    count = 0
    with _db.transaction("expiry"):
        expired_sessions = [k for k, s in _db.sessions.items() if s.expiry < now]
        for k in expired_sessions:
            del _db.sessions[k]
            count += 1
        expired_tokens = [k for k, t in _db.reset_tokens.items() if t.expiry < now]
        for k in expired_tokens:
            del _db.reset_tokens[k]
            count += 1
    return count


# -------------------------------------------------------------------------
# Composite operations (used by app code)
# -------------------------------------------------------------------------


def _create_token() -> str:
    """Generate a 16-character URL-safe session token."""
    return secrets.token_urlsafe(12)


def login(
    user_uuid: UUID,
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
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    if credential.uuid not in _db.credentials:
        raise ValueError(f"Credential {credential.uuid} not found")

    session_key = _create_token()
    user_str = str(user_uuid)
    with _db.transaction("login", user=user_str):
        # Update user
        _db.users[user_uuid].last_seen = now
        _db.users[user_uuid].visits += 1
        # Update credential
        _db.credentials[credential.uuid].sign_count = credential.sign_count
        _db.credentials[credential.uuid].last_used = now
        # Create session
        _db.sessions[session_key] = Session(
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

    now = datetime.now(timezone.utc)
    expiry = now + SESSION_LIFETIME
    session_key = _create_token()

    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")

    user_str = str(user_uuid)
    with _db.transaction("create_credential_session", user=user_str):
        # Update display name if provided
        if display_name:
            _db.users[user_uuid].display_name = display_name

        # Create credential
        _db.credentials[credential.uuid] = credential

        # Create session
        _db.sessions[session_key] = Session(
            user=user_uuid,
            credential=credential.uuid,
            host=host,
            ip=ip,
            user_agent=user_agent,
            expiry=expiry,
        )

        # Delete reset token if provided
        if reset_key:
            if reset_key in _db.reset_tokens:
                del _db.reset_tokens[reset_key]
    return session_key


# -------------------------------------------------------------------------
# Bootstrap (single transaction for initial system setup)
# -------------------------------------------------------------------------


def bootstrap(
    org_name: str = "Organization",
    admin_name: str = "Admin",
    reset_passphrase: str | None = None,
    reset_expiry: datetime | None = None,
) -> str:
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
        The reset passphrase for admin registration.
    """

    # Check if system is already bootstrapped
    for p in _db.permissions.values():
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
        from paskia.authsession import reset_expires  # noqa: PLC0415

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
        _db.permissions[perm_admin_uuid] = perm_admin

        # Create auth:org:admin permission
        perm_org_admin = Permission(
            scope="auth:org:admin",
            display_name="Org Admin",
            orgs={org_uuid: True},  # Grant to org
        )
        perm_org_admin.uuid = perm_org_admin_uuid
        _db.permissions[perm_org_admin_uuid] = perm_org_admin

        # Create organization
        new_org = Org(
            display_name=org_name,
            created_at=now,
        )
        new_org.uuid = org_uuid
        _db.orgs[org_uuid] = new_org

        # Create Administration role with both permissions
        admin_role = Role(
            org=org_uuid,
            display_name="Administration",
            permissions={perm_admin_uuid: True, perm_org_admin_uuid: True},
        )
        admin_role.uuid = role_uuid
        _db.roles[role_uuid] = admin_role

        # Create admin user
        admin_user = User(
            display_name=admin_name,
            role=role_uuid,
            created_at=now,
            last_seen=None,
            visits=0,
        )
        admin_user.uuid = user_uuid
        _db.users[user_uuid] = admin_user

        # Create reset token
        _db.reset_tokens[reset_key] = ResetToken(
            user=user_uuid,
            expiry=reset_expiry,
            token_type="admin bootstrap",
        )

    return reset_passphrase
