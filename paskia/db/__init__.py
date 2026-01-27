"""
Database module for WebAuthn passkey authentication.

Read: Access db() directly, use build_* to convert to public structs.
CTX: get_session_context(key) returns SessionContext with effective permissions.
Write: Functions validate and commit, or raise ValueError.

Usage:
    from paskia import db

    # Read (after init)
    user_data = db.db().users[user_uuid]
    user = db.build_user(user_uuid)

    # Context
    ctx = db.get_session_context(session_key)

    # Write
    db.create_user(user)
"""

from paskia.db.background import (
    start_background,
    start_cleanup,
    stop_background,
    stop_cleanup,
)
from paskia.db.operations import (
    add_permission_to_organization,
    add_permission_to_role,
    bootstrap,
    build_org,
    cleanup_expired,
    create_credential,
    create_credential_session,
    create_organization,
    create_permission,
    create_reset_token,
    create_role,
    create_session,
    create_user,
    delete_credential,
    delete_organization,
    delete_permission,
    delete_reset_token,
    delete_role,
    delete_session,
    delete_sessions_for_user,
    delete_user,
    get_credential_by_id,
    get_credentials_by_user_uuid,
    get_organization,
    get_organization_users,
    get_permission,
    get_permission_by_scope,
    get_permission_organizations,
    get_reset_token,
    get_role,
    get_roles_by_organization,
    get_session,
    get_session_context,
    get_user_by_uuid,
    get_user_organization,
    init,
    list_organizations,
    list_permissions,
    list_sessions_for_user,
    login,
    remove_permission_from_organization,
    remove_permission_from_role,
    rename_permission,
    set_session_host,
    update_credential_sign_count,
    update_organization_name,
    update_permission,
    update_role_name,
    update_session,
    update_user_display_name,
    update_user_role,
    update_user_role_in_organization,
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


def db() -> DB:
    """Get the database instance for direct read access."""
    from paskia.db.operations import _db

    return _db


__all__ = [
    # Types
    "Credential",
    "DB",
    "Org",
    "Permission",
    "ResetToken",
    "Role",
    "Session",
    "SessionContext",
    "User",
    # Instance
    "db",
    "init",
    # Background
    "start_background",
    "stop_background",
    "start_cleanup",
    "stop_cleanup",
    # Builders
    "build_credential",
    "build_org",
    "build_permission",
    "build_reset_token",
    "build_role",
    "build_session",
    "build_user",
    # Read ops
    "get_credential_by_id",
    "get_credentials_by_user_uuid",
    "get_organization",
    "get_organization_users",
    "get_permission",
    "get_permission_by_scope",
    "get_permission_organizations",
    "get_reset_token",
    "get_role",
    "get_roles_by_organization",
    "get_session",
    "get_session_context",
    "get_user_by_uuid",
    "get_user_organization",
    "list_organizations",
    "list_permissions",
    "list_sessions_for_user",
    # Write ops
    "add_permission_to_organization",
    "add_permission_to_role",
    "bootstrap",
    "cleanup_expired",
    "create_credential",
    "create_credential_session",
    "create_organization",
    "create_permission",
    "create_reset_token",
    "create_role",
    "create_session",
    "create_user",
    "delete_credential",
    "delete_organization",
    "delete_permission",
    "delete_reset_token",
    "delete_role",
    "delete_session",
    "delete_sessions_for_user",
    "delete_user",
    "login",
    "remove_permission_from_organization",
    "remove_permission_from_role",
    "rename_permission",
    "set_session_host",
    "update_credential_sign_count",
    "update_organization_name",
    "update_permission",
    "update_role_name",
    "update_session",
    "update_user_display_name",
    "update_user_role",
    "update_user_role_in_organization",
]
