"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.
"""

import asyncio
import logging
from datetime import datetime, timezone

import uuid7

from paskia import authsession, db
from paskia.db import Org, Permission, Role, User
from paskia.util import hostutil, passphrase, tokens


def _init_logger() -> logging.Logger:
    logger = logging.getLogger(__name__)
    if not logger.handlers and not logging.getLogger().handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(h)
        logger.setLevel(logging.INFO)
    return logger


logger = _init_logger()

# Shared log message template for admin reset links
ADMIN_RESET_MESSAGE = """\
%s

👤 Admin  %s
   - Use this link to register a Passkey for the admin user!
"""


async def _create_and_log_admin_reset_link(user_uuid, message, session_type) -> str:
    """Create an admin reset link and log it with the provided message."""
    token = passphrase.generate()
    expiry = authsession.reset_expires()
    db.create_reset_token(
        user_uuid=user_uuid,
        key=tokens.reset_key(token),
        expiry=expiry,
        token_type=session_type,
    )
    reset_link = hostutil.reset_link_url(token)
    logger.info(ADMIN_RESET_MESSAGE, message, reset_link)
    return reset_link


async def bootstrap_system() -> dict:
    """
    Bootstrap the entire system with default data.

    Returns:
        dict: Contains information about created entities and reset link
    """
    # Create permission first - will fail if already exists
    perm0 = Permission(id="auth:admin", display_name="Master Admin")
    db.create_permission(perm0)

    org = Org(uuid7.create(), "Organization")
    db.create_organization(org)

    # After creation, org.permissions now includes the auto-created org admin permission
    # Allow this org to grant global admin explicitly
    db.add_permission_to_organization(str(org.uuid), perm0.id)

    # Create an Administration role granting both org and global admin
    # Compose permissions for Administration role: global admin + org admin auto-perm
    role = Role(
        uuid7.create(),
        org.uuid,
        "Administration",
        permissions=[perm0.id, *org.permissions],
    )
    db.create_role(role)

    user = User(
        uuid=uuid7.create(),
        display_name="Admin",
        role_uuid=role.uuid,
        created_at=datetime.now(timezone.utc),
        visits=0,
    )
    db.create_user(user)

    # Generate reset link and log it
    reset_link = await _create_and_log_admin_reset_link(
        user.uuid, "✅ Bootstrap completed!", "admin bootstrap"
    )

    return {
        "user": user,
        "org": org,
        "role": role,
        "permissions": [
            perm0,
            *[Permission(id=p, display_name="") for p in org.permissions],
        ],
        "reset_link": reset_link,
    }


async def check_admin_credentials() -> bool:
    """
    Check if the admin user needs credentials and create a reset link if needed.

    Returns:
        bool: True if a reset link was created, False if admin already has credentials
    """
    try:
        # Get permission organizations to find admin users
        permission_orgs = db.get_permission_organizations(
            "auth:admin"
        )

        if not permission_orgs:
            return False

        # Get users from the first organization with admin permission
        org_users = db.get_organization_users(
            str(permission_orgs[0].uuid)
        )
        admin_users = [user for user, role in org_users if role == "Administration"]

        if not admin_users:
            return False

        # Check first admin user for credentials
        admin_user = admin_users[0]
        credentials = db.get_credentials_by_user_uuid(
            admin_user.uuid
        )

        if not credentials:
            # Admin exists but has no credentials, create reset link
            await _create_and_log_admin_reset_link(
                admin_user.uuid,
                "⚠️  Admin user has no credentials!",
                "admin registration",
            )
            return True

        return False

    except Exception:
        return False


async def bootstrap_if_needed() -> bool:
    """
    Check if system needs bootstrapping and perform it if necessary.

    Returns:
        bool: True if bootstrapping was performed, False if system was already set up
    """
    try:
        # Check if the admin permission exists - if it does, system is already bootstrapped
        db.get_permission("auth:admin")
        # Permission exists, system is already bootstrapped
        # Check if admin needs credentials (only for already-bootstrapped systems)
        await check_admin_credentials()
        return False
    except Exception:
        # Permission doesn't exist, need to bootstrap
        pass

    # No admin permission found, need to bootstrap
    # Bootstrap creates the admin user AND the reset link, so no need to check credentials after
    await bootstrap_system()
    return True


# CLI interface
async def main():
    """Main CLI entry point for bootstrapping."""
    # Configure logging for CLI usage
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

    await globals.init()


if __name__ == "__main__":
    asyncio.run(main())
