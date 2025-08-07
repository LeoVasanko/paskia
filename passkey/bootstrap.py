"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.
"""

import logging
from datetime import datetime

import uuid7

from . import authsession, globals
from .db import Org, Permission, User
from .util import passphrase, tokens

logger = logging.getLogger(__name__)

# Shared log message template for admin reset links
ADMIN_RESET_MESSAGE = """%s

👤 Admin  %s
   - Use this link to register a Passkey for the admin user!
"""


async def _create_and_log_admin_reset_link(user_uuid, message, session_type) -> str:
    """Create an admin reset link and log it with the provided message."""
    token = passphrase.generate()
    await globals.db.instance.create_session(
        user_uuid=user_uuid,
        key=tokens.reset_key(token),
        expires=authsession.expires(),
        info={"type": session_type},
    )
    reset_link = f"{globals.passkey.instance.origin}/auth/{token}"
    logger.info(ADMIN_RESET_MESSAGE, message, reset_link)
    return reset_link


async def bootstrap_system() -> dict:
    """
    Bootstrap the entire system with default data.

    Returns:
        dict: Contains information about created entities and reset link
    """
    # Create permission first - will fail if already exists
    permission = Permission(id="auth/admin", display_name="Admin")
    await globals.db.instance.create_permission(permission)

    # Create organization
    org_uuid = uuid7.create()
    org = Org(
        id=str(org_uuid),
        options={
            "display_name": "Organization",
            "created_at": datetime.now().isoformat(),
        },
    )
    await globals.db.instance.create_organization(org)

    # Create admin user
    admin_uuid = uuid7.create()
    user = User(
        uuid=admin_uuid,
        display_name="Admin",
        org_uuid=org_uuid,
        role="Admin",
        created_at=datetime.now(),
        visits=0,
    )
    await globals.db.instance.create_user(user)

    # Link user to organization and assign permissions
    await globals.db.instance.add_user_to_organization(
        user_uuid=admin_uuid, org_id=org.id, role="Admin"
    )
    await globals.db.instance.add_permission_to_organization(org.id, permission.id)

    # Generate reset link and log it
    reset_link = await _create_and_log_admin_reset_link(
        admin_uuid, "✅ Bootstrap completed!", "admin bootstrap"
    )

    result = {
        "admin_user": {
            "uuid": str(user.uuid),
            "display_name": user.display_name,
            "role": user.role,
        },
        "organization": {
            "id": org.id,
            "display_name": org.options.get("display_name"),
        },
        "permission": {
            "id": permission.id,
            "display_name": permission.display_name,
        },
        "reset_link": reset_link,
    }

    return result


async def check_admin_credentials() -> bool:
    """
    Check if the admin user needs credentials and create a reset link if needed.

    Returns:
        bool: True if a reset link was created, False if admin already has credentials
    """
    try:
        # Get permission organizations to find admin users
        permission_orgs = await globals.db.instance.get_permission_organizations(
            "auth/admin"
        )

        if not permission_orgs:
            return False

        # Get users from the first organization with admin permission
        org_users = await globals.db.instance.get_organization_users(
            permission_orgs[0].id
        )
        admin_users = [user for user, role in org_users if role == "Admin"]

        if not admin_users:
            return False

        # Check first admin user for credentials
        admin_user = admin_users[0]
        credentials = await globals.db.instance.get_credentials_by_user_uuid(
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
        await globals.db.instance.get_permission("auth/admin")
        # Permission exists, check if admin needs credentials
        await check_admin_credentials()
        return False
    except Exception:
        # Permission doesn't exist, need to bootstrap
        pass

    # No admin permission found, need to bootstrap
    await bootstrap_system()
    return True


# CLI interface
async def main():
    """Main CLI entry point for bootstrapping."""
    await globals.init()
    await bootstrap_if_needed()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
