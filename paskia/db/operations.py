"""
Database for WebAuthn passkey authentication.

Read operations: Access _db directly, use build_* helpers to get public structs.
Context lookup: _db.session_ctx() returns full SessionContext with effective permissions.
Write operations: Functions that validate and commit, or raise ValueError.
"""

import hashlib
import logging
import os
import secrets
from datetime import UTC, datetime
from uuid import UUID

import uuid7

from paskia.config import SESSION_LIFETIME
from paskia.db.jsonl import (
    JsonlStore,
)
from paskia.db.structs import (
    DB,
    Config,
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
_initialized = False


async def init(rp_id: str = "localhost", *args, **kwargs):
    """Load database from JSONL file."""
    global _db, _initialized
    if _initialized:
        _logger.debug("Database already initialized, skipping reload")
        return
    default_path = f"{rp_id}.paskiadb"
    db_path = os.environ.get("PASKIA_DB", default_path)
    await _store.load(db_path, rp_id=rp_id)
    _db = _store.db
    _initialized = True


# -------------------------------------------------------------------------
# Read/lookup functions
# -------------------------------------------------------------------------


def get_user_organization(user_uuid: UUID) -> tuple[Org, str]:
    """Get the organization a user belongs to and their role name.

    Raises ValueError if user not found.

    Call sites:
    - admin_create_user_registration_link: org only
    - admin_get_user_detail: org and role
    - admin_update_user_display_name: org only
    - admin_delete_user_credential: org only
    - admin_delete_user_session: org only
    - admin_update_user_role: org only
    """
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    user = _db.users[user_uuid]
    role = user.role
    return role.org, role.display_name


def get_organization_users(org_uuid: UUID) -> list[tuple[User, str]]:
    """Get all users in an organization with their role names.

    Returns list of (User, role_display_name) tuples.
    """
    org = _db.orgs[org_uuid]
    return [(u, u.role.display_name) for role in org.roles for u in role.users]


def get_user_credential_ids(user_uuid: UUID) -> list[bytes]:
    """Get credential IDs for a user (for WebAuthn exclude lists).

    Returns empty list if user has no credentials.
    """
    assert user_uuid
    return [c.credential_id for c in _db.users[user_uuid].credentials]


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
        new_org = Org.create(display_name=org.display_name)
        new_org.uuid = org.uuid
        _db.orgs[org.uuid] = new_org
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
            org_uuid=org.uuid,
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
        org = _db.orgs[uuid]
        # Remove org from all permissions
        for p in _db.permissions.values():
            p.orgs.pop(uuid, None)
        # Delete roles in this org and their users
        for role in org.roles:
            for user in role.users:
                del _db.users[user.uuid]
            del _db.roles[role.uuid]
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
    if role.org_uuid not in _db.orgs:
        raise ValueError(f"Organization {role.org_uuid} not found")
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
    role = _db.roles[uuid]
    if role.users:
        raise ValueError(f"Cannot delete role {uuid}: users still assigned")
    with _db.transaction("admin:delete_role", ctx):
        del _db.roles[uuid]


def create_user(new_user: User, *, ctx: SessionContext | None = None) -> None:
    """Create a new user."""
    if new_user.uuid in _db.users:
        raise ValueError(f"User {new_user.uuid} already exists")
    if new_user.role_uuid not in _db.roles:
        raise ValueError(f"Role {new_user.role_uuid} not found")
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


def update_user_theme(
    uuid: UUID,
    theme: str,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update user theme preference ('' for auto, 'light', 'dark')."""
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    if theme not in ("", "light", "dark"):
        raise ValueError(f"Invalid theme: {theme}")
    with _db.transaction("update_user_theme", ctx):
        _db.users[uuid].theme = theme


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
        _db.users[uuid].role_uuid = role_uuid


def delete_user(uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete user and their credentials/sessions."""
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    user = _db.users[uuid]
    with _db.transaction("admin:delete_user", ctx):
        # Delete credentials
        for cred in user.credentials:
            del _db.credentials[cred.uuid]
        # Delete sessions
        for sess in user.sessions:
            del _db.sessions[sess.key]
        # Delete reset tokens (iterate over dict items to get correct keys)
        for key, token in list(_db.reset_tokens.items()):
            if token.user_uuid == uuid:
                del _db.reset_tokens[key]
        del _db.users[uuid]


def create_credential(cred: Credential, *, ctx: SessionContext | None = None) -> None:
    """Create a new credential."""
    if cred.uuid in _db.credentials:
        raise ValueError(f"Credential {cred.uuid} already exists")
    if cred.user_uuid not in _db.users:
        raise ValueError(f"User {cred.user_uuid} not found")
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
    cred = _db.credentials[uuid]
    if user_uuid is not None:
        if cred.user_uuid != user_uuid:
            raise ValueError(f"Credential {uuid} does not belong to user {user_uuid}")
    with _db.transaction("delete_credential", ctx):
        # Delete all sessions using this credential
        for sess in cred.sessions:
            print(sess, repr(sess.key))
            del _db.sessions[sess.key]
        del _db.credentials[uuid]


def create_session(
    user_uuid: UUID,
    credential_uuid: UUID,
    host: str,
    ip: str,
    user_agent: str,
    expiry: datetime,
    *,
    ctx: SessionContext | None = None,
) -> str:
    """Create a new session. Returns the session key."""
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    if credential_uuid not in _db.credentials:
        raise ValueError(f"Credential {credential_uuid} not found")
    session = Session.create(
        user=user_uuid,
        credential=credential_uuid,
        host=host,
        ip=ip,
        user_agent=user_agent,
        expiry=expiry,
    )
    if session.key in _db.sessions:
        raise ValueError("Session already exists")
    with _db.transaction("create_session", ctx):
        _db.sessions[session.key] = session
    return session.key


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


def delete_session(
    key: str, *, ctx: SessionContext | None = None, action: str = "delete_session"
) -> None:
    """Delete a session.

    The acting user should be logged via ctx.
    For user logout, pass ctx of the user's session and action="logout".
    For admin terminating a session, pass admin's ctx.
    """
    if key not in _db.sessions:
        raise ValueError("Session not found")
    with _db.transaction(action, ctx):
        del _db.sessions[key]


def delete_sessions_for_user(
    user_uuid: UUID, *, ctx: SessionContext | None = None
) -> None:
    """Delete all sessions for a user.

    The acting user should be logged via ctx.
    For user logout-all, pass ctx of the user's session.
    For admin bulk termination, pass admin's ctx.
    """
    user = _db.users.get(user_uuid)
    if not user:
        return
    with _db.transaction("admin:delete_sessions_for_user", ctx):
        for sess in user.sessions:
            del _db.sessions[sess.key]


def create_reset_token(
    user_uuid: UUID,
    expiry: datetime,
    token_type: str,
    *,
    ctx: SessionContext | None = None,
    user: str | None = None,
) -> str:
    """Create a reset token and return the passphrase.

    The acting user should be logged via ctx.
    For self-service (user creating own recovery link), pass user's ctx.
    For admin operations, pass admin's ctx.
    For system operations (bootstrap), pass neither to log no user.
    For API operations where ctx is not available but user is known, pass user.

    Returns:
        The passphrase to give to the user.
    """
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    token, passphrase = ResetToken.create(
        user=user_uuid, expiry=expiry, token_type=token_type
    )
    if token.key in _db.reset_tokens:
        raise ValueError("Reset token already exists")
    with _db.transaction("create_reset_token", ctx, user=user):
        _db.reset_tokens[token.key] = token
    return passphrase


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
    now = datetime.now(UTC)
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
    credential_uuid: UUID,
    sign_count: int,
    host: str,
    ip: str,
    user_agent: str,
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
    now = datetime.now(UTC)
    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")
    if credential_uuid not in _db.credentials:
        raise ValueError(f"Credential {credential_uuid} not found")

    session = Session.create(
        user=user_uuid,
        credential=credential_uuid,
        host=host,
        ip=ip,
        user_agent=user_agent,
        expiry=expiry,
    )
    user_str = str(user_uuid)
    with _db.transaction("login", user=user_str):
        # Update user
        _db.users[user_uuid].last_seen = now
        _db.users[user_uuid].visits += 1
        # Update credential
        _db.credentials[credential_uuid].sign_count = sign_count
        _db.credentials[credential_uuid].last_used = now
        # Create session
        _db.sessions[session.key] = session
    return session.key


def create_credential_session(
    user_uuid: UUID,
    credential: Credential,
    host: str,
    ip: str,
    user_agent: str,
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

    now = datetime.now(UTC)
    expiry = now + SESSION_LIFETIME

    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")

    session = Session.create(
        user=user_uuid,
        credential=credential.uuid,
        host=host,
        ip=ip,
        user_agent=user_agent,
        expiry=expiry,
    )
    user_str = str(user_uuid)
    with _db.transaction("create_credential_session", user=user_str):
        # Update display name if provided
        if display_name:
            _db.users[user_uuid].display_name = display_name

        # Create credential
        _db.credentials[credential.uuid] = credential

        # Create session
        _db.sessions[session.key] = session

        # Delete reset token if provided
        if reset_key:
            if reset_key in _db.reset_tokens:
                del _db.reset_tokens[reset_key]
    return session.key


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

    This is the only way to create a new database file.
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

    # Set reset token expiry (passphrase generated by ResetToken.create)
    if reset_expiry is None:
        from paskia.authsession import reset_expires  # noqa: PLC0415

        reset_expiry = reset_expires()

    now = datetime.now(UTC)

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
        new_org = Org.create(display_name=org_name)
        new_org.uuid = org_uuid
        _db.orgs[org_uuid] = new_org

        # Create Administration role with both permissions
        admin_role = Role(
            org_uuid=org_uuid,
            display_name="Administration",
            permissions={perm_admin_uuid: True, perm_org_admin_uuid: True},
        )
        admin_role.uuid = role_uuid
        _db.roles[role_uuid] = admin_role

        # Create admin user
        admin_user = User(
            display_name=admin_name,
            role_uuid=role_uuid,
            created_at=now,
            last_seen=None,
            visits=0,
        )
        admin_user.uuid = user_uuid
        _db.users[user_uuid] = admin_user

        # Create reset token
        reset_token, reset_passphrase = ResetToken.create(
            user=user_uuid,
            expiry=reset_expiry,
            token_type="admin bootstrap",
            passphrase=reset_passphrase,
        )
        _db.reset_tokens[reset_token.key] = reset_token

    return reset_passphrase


# -------------------------------------------------------------------------
# Config operations
# -------------------------------------------------------------------------


def get_config() -> Config:
    """Get the stored configuration."""
    return _db.config


async def set_config(config: Config) -> None:
    """Update the stored configuration."""
    async with _db.transaction("update_config"):
        _db.config = config
