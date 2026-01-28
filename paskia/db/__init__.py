"""
Database module for WebAuthn passkey authentication.

Read: Access data() directly, use build_* to convert to public structs.
CTX: data().session_ctx(key) returns SessionContext with effective permissions.
Write: Functions validate and commit, or raise ValueError.

Usage:
    from paskia import db

    # Read (after init)
    user_data = db.data().users[user_uuid]
    user = db.build_user(user_uuid)

    # Context
    ctx = db.data().session_ctx(session_key)

    # Write
    db.create_user(user)
"""

import paskia.db.operations as operations
from paskia.db.background import (
    start_background,
    start_cleanup,
    stop_background,
    stop_cleanup,
)
from paskia.db.operations import (
    add_permission_to_org,
    add_permission_to_role,
    bootstrap,
    cleanup_expired,
    create_credential,
    create_credential_session,
    create_org,
    create_permission,
    create_reset_token,
    create_role,
    create_session,
    create_user,
    delete_credential,
    delete_org,
    delete_permission,
    delete_reset_token,
    delete_role,
    delete_session,
    delete_sessions_for_user,
    delete_user,
    get_organization_users,
    get_reset_token,
    get_user_credential_ids,
    get_user_organization,
    init,
    login,
    remove_permission_from_org,
    remove_permission_from_role,
    set_session_host,
    update_credential_sign_count,
    update_org_name,
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


def data() -> DB:
    """Get the database instance for direct read access."""
    return operations._db


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
    "data",
    "init",
    # Background
    "start_background",
    "stop_background",
    "start_cleanup",
    "stop_cleanup",
    # Builders
    "build_credential",
    "build_permission",
    "build_reset_token",
    "build_role",
    "build_session",
    "build_user",
    # Read ops
    "get_organization_users",
    "get_reset_token",
    "get_user_credential_ids",
    "get_user_organization",
    # Write ops
    "add_permission_to_org",
    "add_permission_to_role",
    "bootstrap",
    "cleanup_expired",
    "create_credential",
    "create_credential_session",
    "create_org",
    "create_permission",
    "create_reset_token",
    "create_role",
    "create_session",
    "create_user",
    "delete_credential",
    "delete_org",
    "delete_permission",
    "delete_reset_token",
    "delete_role",
    "delete_session",
    "delete_sessions_for_user",
    "delete_user",
    "login",
    "remove_permission_from_org",
    "remove_permission_from_role",
    "set_session_host",
    "update_credential_sign_count",
    "update_org_name",
    "update_permission",
    "update_role_name",
    "update_session",
    "update_user_display_name",
    "update_user_role",
    "update_user_role_in_organization",
]
