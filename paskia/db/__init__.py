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
from paskia.db.bootstrap import bootstrap
from paskia.db.jsonl import load_readonly
from paskia.db.lifecycle import cleanup_expired, init
from paskia.db.operations import (
    add_permission_to_org,
    add_permission_to_role,
    create_credential,
    create_credential_session,
    create_oid_client,
    create_org,
    create_permission,
    create_reset_token,
    create_role,
    create_user,
    delete_credential,
    delete_oid_client,
    delete_org,
    delete_permission,
    delete_reset_token,
    delete_role,
    delete_session,
    delete_sessions_for_user,
    delete_user,
    is_username_taken,
    login,
    oidc_login,
    remove_permission_from_org,
    remove_permission_from_role,
    reset_oid_client_secret,
    set_session_host,
    update_config,
    update_credential_sign_count,
    update_oid_client,
    update_org_name,
    update_permission,
    update_role_name,
    update_session,
    update_user_display_name,
    update_user_info,
    update_user_role,
)
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


def data() -> DB:
    """Get the database instance for direct read access."""
    return operations._db


__all__ = [
    # Types
    "Config",
    "Credential",
    "DB",
    "Client",
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
    "load_readonly",
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
    "oidc_login",
    "remove_permission_from_org",
    "remove_permission_from_role",
    "set_session_host",
    "update_config",
    "update_credential_sign_count",
    "update_org_name",
    "update_permission",
    "update_role_name",
    "update_session",
    "update_user_display_name",
    "update_user_info",
    "update_user_role",
    "is_username_taken",
    # OIDC
    "create_oid_client",
    "update_oid_client",
    "reset_oid_client_secret",
    "delete_oid_client",
]
