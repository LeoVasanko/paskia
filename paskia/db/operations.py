"""
Database for WebAuthn passkey authentication.

Read operations: Access _db directly, use build_* helpers to get public structs.
Context lookup: _db.session_ctx() returns full SessionContext with effective permissions.
Write operations: Functions that validate and commit, or raise ValueError.
"""

import logging
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import uuid7

from paskia import oidc_notify
from paskia.config import SESSION_LIFETIME
from paskia.db.structs import (
    DB,
    Client,
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
from paskia.util.crypto import hash_secret
from paskia.util.nameutil import slugify_name

_logger = logging.getLogger(__name__)

# Sentinel for distinguishing "not provided" from None
_UNSET = object()

# Global database instance (empty until init() loads data)
_db = DB(config=Config(rp_id="uninitialized.invalid"))


def is_username_taken(username: str, exclude_uuid: UUID | None = None) -> bool:
    """Check if a preferred_username is already taken by another user."""
    if not username:
        return False
    for user in _db.users.values():
        if user.preferred_username == username:
            if exclude_uuid is None or user.uuid != exclude_uuid:
                return True
    return False


# -------------------------------------------------------------------------
# Write operations (validate, modify, commit or raise ValueError)
# -------------------------------------------------------------------------


def update_config(config: Config) -> None:
    """Update the stored configuration."""
    with _db.transaction("update_config"):
        _db.config = config


def create_permission(perm: Permission, *, ctx: SessionContext | None = None) -> None:
    """Create a new permission."""
    if perm.uuid in _db.permissions:
        raise ValueError(f"Permission {perm.uuid} already exists")
    with _db.transaction("admin:create_permission", ctx):
        perm.store()


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
        _db.permissions[uuid].delete()


def create_org(org: Org, *, ctx: SessionContext | None = None) -> None:
    """Create a new organization with an Administration role.

    Automatically creates an 'Administration' role with auth:org:admin permission.
    """
    if org.uuid in _db.orgs:
        raise ValueError(f"Organization {org.uuid} already exists")
    now = datetime.now(UTC)
    with _db.transaction("admin:create_org", ctx):
        new_org = Org.create(display_name=org.display_name, created_at=now)
        new_org.uuid = org.uuid
        new_org.store()
        # Create Administration role with org admin permission

        admin_role_uuid = uuid7.create(now)
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
        admin_role.store()


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
        _db.orgs[uuid].delete()


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
        role.store()


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
        _db.roles[uuid].delete()


def create_user(new_user: User, *, ctx: SessionContext | None = None) -> None:
    """Create a new user."""
    if new_user.uuid in _db.users:
        raise ValueError(f"User {new_user.uuid} already exists")
    if new_user.role_uuid not in _db.roles:
        raise ValueError(f"Role {new_user.role_uuid} not found")
    with _db.transaction("admin:create_user", ctx):
        new_user.store()


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

    If the user's preferred_username is currently None, this will auto-fill it
    with a slugified version of the display name (if unique and non-empty).
    """
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")
    display_name = (display_name or "").strip()
    if not display_name:
        raise ValueError("Display name cannot be empty")
    user = _db.users[uuid]
    with _db.transaction("update_user_display_name", ctx):
        user.display_name = display_name
        # Auto-fill preferred_username if not already set
        if user.preferred_username is None:
            slug = slugify_name(display_name)
            if slug and not is_username_taken(slug, exclude_uuid=uuid):
                user.preferred_username = slug


def update_user_info(
    uuid: UUID,
    *,
    display_name: str | object = _UNSET,
    theme: str | object = _UNSET,
    email: str | None | object = _UNSET,
    preferred_username: str | None | object = _UNSET,
    telephone: str | None | object = _UNSET,
    ctx: SessionContext | None = None,
) -> None:
    """Update user profile information.

    Pass only the fields you want to update. Use None to clear optional fields.
    This does NOT auto-fill preferred_username - use update_user_display_name
    for the registration flow where auto-fill is desired.

    Args:
        uuid: User UUID
        display_name: User display name (cannot be empty)
        theme: Theme preference ('' for auto, 'light', 'dark')
        email: Email address (None to clear)
        preferred_username: Username for OIDC claims (None to clear, must be unique)
        telephone: Phone number (None to clear)
        ctx: Session context for audit logging
    """
    if isinstance(uuid, str):
        uuid = UUID(uuid)
    if uuid not in _db.users:
        raise ValueError(f"User {uuid} not found")

    user = _db.users[uuid]

    # Validate all fields before transaction
    if display_name is not _UNSET:
        display_name = (display_name or "").strip()
        if not display_name:
            raise ValueError("Display name cannot be empty")

    if theme is not _UNSET:
        if theme not in ("", "light", "dark"):
            raise ValueError(f"Invalid theme: {theme}")

    if email is not _UNSET and email is not None:
        email = (email or "").strip()
        if not email:
            email = None
        elif "@" not in email or len(email) > 254:
            raise ValueError("Invalid email format")

    if preferred_username is not _UNSET and preferred_username is not None:
        preferred_username = (preferred_username or "").strip()
        if not preferred_username:
            raise ValueError("Preferred username cannot be empty (use None to clear)")
        if len(preferred_username) > 128:
            raise ValueError("preferred_username too long")
        if is_username_taken(preferred_username, exclude_uuid=uuid):
            raise ValueError("Username already taken")

    if telephone is not _UNSET and telephone is not None:
        telephone = (telephone or "").strip()
        if not telephone:
            telephone = None
        elif len(telephone) > 32:
            raise ValueError("telephone too long")

    with _db.transaction("update_user_info", ctx):
        if display_name is not _UNSET:
            user.display_name = display_name
        if theme is not _UNSET:
            user.theme = theme
        if email is not _UNSET:
            user.email = email
        if preferred_username is not _UNSET:
            user.preferred_username = preferred_username
        if telephone is not _UNSET:
            user.telephone = telephone


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
    with _db.transaction("admin:delete_user", ctx):
        _db.users[uuid].delete()


def create_credential(cred: Credential, *, ctx: SessionContext | None = None) -> None:
    """Create a new credential."""
    if cred.uuid in _db.credentials:
        raise ValueError(f"Credential {cred.uuid} already exists")
    if cred.user_uuid not in _db.users:
        raise ValueError(f"User {cred.user_uuid} not found")
    with _db.transaction("create_credential", ctx):
        cred.store()


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
        cred.delete()


def update_session(
    key: bytes,
    host: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    validated: datetime | None = None,
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
        if validated is not None:
            s.validated = validated


def set_session_host(
    key: bytes, host: str, *, ctx: SessionContext | None = None
) -> None:
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

    oidc_notify.schedule_notifications([key])
    with _db.transaction(action, ctx):
        _db.sessions[key].delete()


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

    keys = [s.key for s in user.sessions]
    oidc_notify.schedule_notifications(keys)
    with _db.transaction("admin:delete_sessions_for_user", ctx):
        for sess in user.sessions:
            sess.delete()


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
        token.store()
    return passphrase


def delete_reset_token(key: bytes, *, ctx: SessionContext | None = None) -> None:
    """Delete a reset token."""
    if key not in _db.reset_tokens:
        raise ValueError("Reset token not found")
    with _db.transaction("delete_reset_token", ctx):
        _db.reset_tokens[key].delete()


# -------------------------------------------------------------------------
# Composite operations (used by app code)
# -------------------------------------------------------------------------


def login(
    user_uuid: UUID,
    credential_uuid: UUID,
    sign_count: int,
    host: str,
    ip: str,
    user_agent: str,
    duration: timedelta = SESSION_LIFETIME,
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

    # Generate token and derive key
    token = secrets.token_urlsafe(12)

    session = Session.create(
        user=user_uuid,
        credential=credential_uuid,
        key=hash_secret("cookie", token),
        host=host,
        ip=ip,
        user_agent=user_agent,
        validated=now,
    )
    user_str = str(user_uuid)
    with _db.transaction("login", user=user_str):
        session.store(now)
        # Update credential
        _db.credentials[credential_uuid].sign_count = sign_count
        _db.credentials[credential_uuid].last_used = now
    return token


def oidc_login(
    session: Session,
    credential_uuid: UUID,
    sign_count: int,
) -> None:
    """Store an OIDC session and update credential in a single transaction.

    The caller is responsible for generating the token, deriving the key,
    and creating the Session object.  This function only handles the
    database transaction.

    Updates:
    - user.last_seen, user.visits
    - credential.sign_count, credential.last_used
    Stores:
    - the provided session
    """
    now = datetime.now(UTC)
    user_str = str(session.user_uuid)
    with _db.transaction("oidc_login", user=user_str):
        session.store(now)
        # Update credential
        _db.credentials[credential_uuid].sign_count = sign_count
        _db.credentials[credential_uuid].last_used = now


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

    if user_uuid not in _db.users:
        raise ValueError(f"User {user_uuid} not found")

    # Generate token and derive key
    token = secrets.token_urlsafe(12)
    key = hash_secret("cookie", token)

    session = Session.create(
        user=user_uuid,
        credential=credential.uuid,
        key=key,
        host=host,
        ip=ip,
        user_agent=user_agent,
        validated=now,
    )
    user_str = str(user_uuid)
    with _db.transaction("create_credential_session", user=user_str):
        # Update display name if provided
        if display_name:
            _db.users[user_uuid].display_name = display_name

        # Align credential timestamps with transaction time
        credential.created_at = now
        credential.last_used = now
        credential.last_verified = now

        # Create credential
        credential.store()

        # Store session and record visit
        session.store(now)

        # Delete reset token if provided
        if reset_key:
            reset_token = _db.reset_tokens.get(reset_key)
            if reset_token:
                reset_token.delete()
    return token


# -------------------------------------------------------------------------
# OIDC Provider operations
# -------------------------------------------------------------------------


def create_oid_client(client: Client, *, ctx: SessionContext | None = None) -> None:
    """Create a new OIDC client."""
    if client.uuid in _db.oidc.clients:
        raise ValueError(f"OIDC client {client.uuid} already exists")
    with _db.transaction("admin:create_oid_client", ctx):
        _db.oidc.clients[client.uuid] = client


def update_oid_client(
    client_uuid: UUID,
    name: str | None = None,
    redirect_uris: list[str] | None = None,
    secret_hash: bytes | None = None,
    backchannel_logout_uri: str | None = _UNSET,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Update an OIDC client's name, redirect URIs, and/or secret."""
    if client_uuid not in _db.oidc.clients:
        raise ValueError(f"OIDC client {client_uuid} not found")

    client = _db.oidc.clients[client_uuid]
    changes = {}

    if name is not None and name != client.name:
        changes["name"] = name
    if redirect_uris is not None and redirect_uris != client.redirect_uris:
        changes["redirect_uris"] = redirect_uris
    if secret_hash is not None and secret_hash != client.client_secret_hash:
        changes["client_secret_hash"] = secret_hash
    if (
        backchannel_logout_uri is not _UNSET
        and backchannel_logout_uri != client.backchannel_logout_uri
    ):
        changes["backchannel_logout_uri"] = backchannel_logout_uri

    if not changes:
        return  # No changes to make

    new_logout_uri = (
        backchannel_logout_uri
        if backchannel_logout_uri is not _UNSET
        else client.backchannel_logout_uri
    )

    with _db.transaction("admin:update_oid_client", ctx):
        # Create updated client with new values
        updated_client = Client(
            client_secret_hash=secret_hash
            if secret_hash is not None
            else client.client_secret_hash,
            name=name if name is not None else client.name,
            redirect_uris=redirect_uris
            if redirect_uris is not None
            else client.redirect_uris,
            backchannel_logout_uri=new_logout_uri,
        )
        updated_client.uuid = client.uuid
        _db.oidc.clients[client_uuid] = updated_client


def reset_oid_client_secret(
    client_uuid: UUID,
    new_secret_hash: bytes,
    *,
    ctx: SessionContext | None = None,
) -> None:
    """Reset an OIDC client's secret."""
    if client_uuid not in _db.oidc.clients:
        raise ValueError(f"OIDC client {client_uuid} not found")
    client = _db.oidc.clients[client_uuid]
    with _db.transaction("admin:reset_oid_client_secret", ctx):
        updated = Client(
            client_secret_hash=new_secret_hash,
            name=client.name,
            redirect_uris=client.redirect_uris,
            backchannel_logout_uri=client.backchannel_logout_uri,
        )
        updated.uuid = client.uuid
        _db.oidc.clients[client_uuid] = updated


def delete_oid_client(client_uuid: UUID, *, ctx: SessionContext | None = None) -> None:
    """Delete an OIDC client."""
    if client_uuid not in _db.oidc.clients:
        raise ValueError(f"OIDC client {client_uuid} not found")
    with _db.transaction("admin:delete_oid_client", ctx):
        del _db.oidc.clients[client_uuid]
