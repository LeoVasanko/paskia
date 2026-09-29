"""
Database module for WebAuthn passkey authentication.

Read: Access data() directly for structs.
CTX: data().session_ctx(key) returns SessionContext with effective permissions.
Write: Functions validate and commit, or raise ValueError.

Usage:
    from paskia import db

    # Read (after init)
    user_data = db.data().users[user_uuid]

    # Context
    ctx = db.data().session_ctx(session_key)

    # Write
    db.create_user(user)
"""

import paskia.db.operations as operations
from paskia.db.bootstrap import bootstrap
from paskia.db.operations import (
    add_permission_to_org,
    add_permission_to_role,
    create_credential,
    create_credential_session,
    create_domain,
    create_oid_client,
    create_org,
    create_permission,
    create_reset_token,
    create_role,
    create_user,
    delete_credential,
    delete_domain,
    delete_oid_client,
    delete_org,
    delete_permission,
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
    update_credential_sign_count,
    update_domain,
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
    OIDC,
    Client,
    Config,
    Credential,
    DomainConfig,
    Org,
    Permission,
    RemoteConfig,
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
    "OIDC",
    "Org",
    "Permission",
    "DomainConfig",
    "RemoteConfig",
    "ResetToken",
    "Role",
    "Session",
    "SessionContext",
    "User",
    # Instance
    "data",
    # Read ops
    # Write ops
    "add_permission_to_org",
    "add_permission_to_role",
    "bootstrap",
    "create_credential",
    "create_credential_session",
    "create_org",
    "create_permission",
    "create_domain",
    "create_reset_token",
    "create_role",
    "create_user",
    "delete_credential",
    "delete_org",
    "delete_permission",
    "delete_domain",
    "delete_role",
    "delete_session",
    "delete_sessions_for_user",
    "delete_user",
    "login",
    "oidc_login",
    "remove_permission_from_org",
    "remove_permission_from_role",
    "update_credential_sign_count",
    "update_org_name",
    "update_permission",
    "update_domain",
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
