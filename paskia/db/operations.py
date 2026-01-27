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


def get_permission(uuid: UUID) -> Permission | None:
    """Get permission by UUID.

    Call sites:
    - Normalize permission IDs to UUIDs when creating a role (admin.py:277)
    - Verify permission exists when adding to role (admin.py:349)
    - Check permission scope when removing from role to prevent losing admin access (admin.py:385)
    - Get permission to check scope for admin access check (admin.py:392)
    - Check if new role has admin permissions when user changes own role (admin.py:509)
    - Get permission for updating its details (admin.py:977)
    - Get permission for renaming its scope (admin.py:1031)
    - Get permission to check scope before deleting (admin.py:1071)
    """
    return _db.permissions.get(uuid)


def get_permission_by_scope(scope: str) -> Permission | None:
    """Get permission by scope identifier.

    Call sites:
    - Check if system is already bootstrapped by looking for auth:admin permission (bootstrap.py:113)
    """
    for p in _db.permissions.values():
        if p.scope == scope:
            return p
    return None


def get_permissions_by_scope(scope: str) -> list[Permission]:
    """Get all permissions with the given scope.

    Since scopes are not unique, this returns all matching permissions.
    Use this for scope-based permission checking.
    """
    return [p for p in _db.permissions.values() if p.scope == scope]


def list_permissions() -> list[Permission]:
    """List all permissions.

    Call sites:
    - List permissions during migration to identify org-specific admin permissions (migrate/__init__.py:84)
    - List permissions to delete organization-specific permissions when deleting org (admin.py:193)
    - List permissions to check admin permissions when updating permission domain (admin.py:847)
    - List permissions to check admin permissions when deleting permission (admin.py:882)
    - Admin API endpoint to list permissions (admin.py:914)
    """
    return list(_db.permissions.values())


def get_organization(uuid: UUID) -> Org | None:
    """Get organization by UUID.

    Call sites:
    - Get organization when creating a role to check grantable permissions (admin.py:271)
    - Get organization when adding permission to role to check if org can grant it (admin.py:352)
    """
    return _db.orgs.get(uuid)


def list_organizations() -> list[Org]:
    """List all organizations.

    Call sites:
    - List organizations during migration (migrate/__init__.py:131)
    - Admin API endpoint to list organizations (admin.py:94)
    """
    return list(_db.orgs.values())


def get_organization_users(org_uuid: UUID) -> list[tuple[User, str]]:
    """Get all users in an organization with their role names.

    Call sites:
    - Get users for each organization in the admin list orgs API (admin.py:108)
    - Get users from organizations with auth:admin for reset targets (reset.py:31,42,58)
    - Get users from organization to check if admin has credentials (bootstrap.py:73)
    """
    role_map = {
        rid: r.display_name for rid, r in _db.roles.items() if r.org == org_uuid
    }
    return [(u, role_map[u.role]) for u in _db.users.values() if u.role in role_map]


def get_role(uuid: UUID) -> Role | None:
    """Get role by UUID.

    Call sites:
    - Get role to update its display name (admin.py:312)
    - Get role to add permission to it (admin.py:344)
    - Get role to remove permission from it (admin.py:380)
    - Get role to delete it (admin.py:421)
    """
    return _db.roles.get(uuid)


def get_roles_by_organization(org_uuid: UUID) -> list[Role]:
    """Get all roles in an organization.

    Call sites:
    - Get roles by organization when creating a user to find the role by name (admin.py:459)
    - Get roles by organization when updating user role to validate the new role name (admin.py:498)
    """
    return [r for r in _db.roles.values() if r.org == org_uuid]


def get_user_by_uuid(uuid: UUID) -> User | None:
    """Get user by UUID.

    Call sites:
    - Get user for WebAuthn credential registration (ws.py:68)
    - Get user from reset token for registration info (api.py:127)
    - Get user for listing user credentials in admin API (admin.py:594)
    """
    return _db.users.get(uuid)


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


def get_credential_by_id(credential_id: bytes) -> Credential | None:
    """Get credential by credential_id (the authenticator's ID).

    Call sites:
    - Get credential by ID for WebAuthn authentication (ws.py:132)
    - Get credential by ID for remote authentication (remote.py:325)
    """
    for c in _db.credentials.values():
        if c.credential_id == credential_id:
            return c
    return None


def get_credentials_by_user_uuid(user_uuid: UUID) -> list[Credential]:
    """Get all credentials for a user.

    Call sites:
    - Get credentials for user during registration to exclude existing ones (ws.py:74)
    - Get credentials for session user during reauth to restrict to user's credentials (ws.py:117)
    - Get credentials to check if user has existing ones for reset token type (admin.py:548)
    - Get credentials for user details API (admin.py:595)
    - Get credentials to check if admin user has credentials (bootstrap.py:81)
    - Get credentials for user info formatting (userinfo.py:51)
    """
    return [c for c in _db.credentials.values() if c.user == user_uuid]


def get_session(key: str) -> Session | None:
    """Get session by key.

    Call sites:
    - Get session to delete it (admin.py:799)
    - Get session to validate token (authsession.py:45)
    - Get session to refresh it (authsession.py:59)
    - Get session to delete it in user API (user.py:94)
    """
    return _db.sessions.get(key)


def list_sessions_for_user(user_uuid: UUID) -> list[Session]:
    """Get all active sessions for a user.

    Call sites:
    - List sessions for user info (userinfo.py:75)
    - List sessions for user details API (admin.py:651)
    """
    return [s for s in _db.sessions.values() if s.user == user_uuid]


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
    from paskia.util.hostutil import normalize_host

    if session_key not in _db.sessions:
        return None

    s = _db.sessions[session_key]
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
    with _db.transaction("Created permission", ctx):
        _db.permissions[perm.uuid] = perm


def update_permission(perm: Permission, *, ctx: SessionContext | None = None) -> None:
    """Update a permission's scope, display_name, and domain."""
    if perm.uuid not in _db.permissions:
        raise ValueError(f"Permission {perm.uuid} not found")
    with _db.transaction("Updated permission", ctx):
        _db.permissions[perm.uuid].scope = perm.scope
        _db.permissions[perm.uuid].display_name = perm.display_name
        _db.permissions[perm.uuid].domain = perm.domain


def rename_permission(
    uuid: UUID,
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
    if uuid not in _db.permissions:
        raise ValueError(f"Permission {uuid} not found")

    with _db.transaction("Renamed permission", ctx):
        # Update the permission
        _db.permissions[uuid].scope = new_scope
        _db.permissions[uuid].display_name = display_name
        _db.permissions[uuid].domain = domain


def delete_permission(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete a permission and remove it from all roles."""
    if uuid not in _db.permissions:
        raise ValueError(f"Permission {uuid} not found")
    with _db.transaction("Deleted permission", ctx):
        # Remove this permission from all roles
        for role in _db.roles.values():
            role.permissions.pop(uuid, None)
        del _db.permissions[uuid]


def create_organization(org: Org, *, ctx: SessionContext | None = None) -> None:
    """Create a new organization with an Administration role.

    Automatically creates an 'Administration' role with auth:org:admin permission.
    """
    if org.uuid in _db.orgs:
        raise ValueError(f"Organization {org.uuid} already exists")
    with _db.transaction("Created organization", ctx):
        new_org = Org(
            display_name=org.display_name, created_at=datetime.now(timezone.utc)
        )
        _db.orgs[org.uuid] = new_org
        new_org.uuid = org.uuid
        # Create Administration role with org admin permission
        import uuid7

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


def update_organization_name(
    uuid: UUID,
    display_name: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update organization display name."""
    if uuid not in _db.orgs:
        raise ValueError(f"Organization {uuid} not found")
    with _db.transaction("Renamed organization", ctx):
        _db.orgs[uuid].display_name = display_name


def delete_organization(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete organization and all its roles/users."""
    if uuid not in _db.orgs:
        raise ValueError(f"Organization {uuid} not found")
    with _db.transaction("Deleted organization", ctx):
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


def add_permission_to_organization(
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

    with _db.transaction("Granted org permission", ctx):
        _db.permissions[permission_uuid].orgs[org_uuid] = True


def remove_permission_from_organization(
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

    with _db.transaction("Revoked org permission", ctx):
        _db.permissions[permission_uuid].orgs.pop(org_uuid, None)


def create_role(role: Role, *, ctx: SessionContext | None = None) -> None:
    """Create a new role."""
    if role.uuid in _db.roles:
        raise ValueError(f"Role {role.uuid} already exists")
    if role.org not in _db.orgs:
        raise ValueError(f"Organization {role.org} not found")
    with _db.transaction("Created role", ctx):
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
    with _db.transaction("Renamed role", ctx):
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
    with _db.transaction("Granted role permission", ctx):
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
    with _db.transaction("Revoked role permission", ctx):
        _db.roles[role_uuid].permissions.pop(permission_uuid, None)


def delete_role(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete a role."""
    if uuid not in _db.roles:
        raise ValueError(f"Role {uuid} not found")
    # Check no users have this role
    if any(u.role == uuid for u in _db.users.values()):
        raise ValueError(f"Cannot delete role {uuid}: users still assigned")
    with _db.transaction("Deleted role", ctx):
        del _db.roles[uuid]


def create_user(new_user: User, *, ctx: SessionContext | None = None) -> None:
    """Create a new user."""
    if new_user.uuid in _db.users:
        raise ValueError(f"User {new_user.uuid} already exists")
    if new_user.role not in _db.roles:
        raise ValueError(f"Role {new_user.role} not found")
    with _db.transaction("Created user", ctx):
        _db.users[new_user.uuid] = new_user


def update_user_display_name(
    uuid: UUID,
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
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    # For self-service, derive user from the uuid being modified
    user_str = str(uuid) if not ctx else None
    with _db.transaction("Renamed user", ctx, user=user_str):
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
    with _db.transaction("Changed user role", ctx):
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
    with _db.transaction("Changed user role", ctx):
        _db.users[user_uuid].role = new_role_uuid


def delete_user(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete user and their credentials/sessions."""
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    with _db.transaction("Deleted user", ctx):
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
    with _db.transaction("Added credential", ctx):
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
    with _db.transaction("Updated credential", ctx):
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
    with _db.transaction("Deleted credential", ctx):
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
    with _db.transaction("Created session", ctx):
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
    with _db.transaction("Updated session", ctx):
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

    For logout (user deleting own session), ctx can be None and user is derived from session.
    For admin operations, ctx should be provided.
    """
    if key not in _db.sessions:
        raise ValueError("Session not found")
    # For self-service logout, derive user from the session being deleted
    user_str = str(_db.sessions[key].user) if not ctx else None
    with _db.transaction("Deleted session", ctx, user=user_str):
        del _db.sessions[key]


def delete_sessions_for_user(
    user_uuid: UUID, *, ctx: SessionContext | None = None
) -> None:
    """Delete all sessions for a user.

    For logout-all (user deleting own sessions), ctx can be None and user is derived from user_uuid.
    For admin operations, ctx should be provided.
    """
    # For self-service, derive user from the user_uuid param
    user_str = str(user_uuid) if not ctx else None
    with _db.transaction("Deleted user sessions", ctx, user=user_str):
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

    For self-service (user creating own recovery link), ctx can be None and user is derived from user_uuid.
    For admin operations, ctx should be provided.
    """
    key = _reset_key(passphrase)
    if key in _db.reset_tokens:
        raise ValueError("Reset token already exists")
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    # For self-service, derive user from the user_uuid param
    user_str = str(user_uuid) if not ctx else None
    with _db.transaction("Created reset token", ctx, user=user_str):
        _db.reset_tokens[key] = ResetToken(
            user=user_uuid, expiry=expiry, token_type=token_type
        )


def delete_reset_token(key: bytes, *, ctx: SessionContext | None = None) -> None:
    """Delete a reset token."""
    if key not in _db.reset_tokens:
        raise ValueError("Reset token not found")
    with _db.transaction("Deleted reset token", ctx):
        del _db.reset_tokens[key]


# -------------------------------------------------------------------------
# Cleanup (called by background task)
# -------------------------------------------------------------------------


def cleanup_expired() -> int:
    """Remove expired sessions and reset tokens. Returns count removed."""
    now = datetime.now(timezone.utc)
    count = 0
    with _db.transaction("Cleaned up expired"):
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
    with _db.transaction("User logged in", user=user_str):
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
    from paskia.config import SESSION_LIFETIME

    now = datetime.now(timezone.utc)
    expiry = now + SESSION_LIFETIME
    session_key = _create_token()

    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")

    user_str = str(user_uuid)
    with _db.transaction("Registered credential", user=user_str):
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
    import uuid7

    from paskia.authsession import reset_expires
    from paskia.util.passphrase import generate as generate_passphrase

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
