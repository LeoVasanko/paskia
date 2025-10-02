"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.
"""

import asyncio
import logging
from datetime import datetime

import uuid7

from . import authsession, globals
from .db import Org, Permission, Role, User
from .util import hostutil, passphrase, tokens


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
    await globals.db.instance.create_session(
        user_uuid=user_uuid,
        key=tokens.reset_key(token),
        expires=authsession.expires(),
        info={"type": session_type},
    )
    base = hostutil.auth_site_base_url()
    reset_link = f"{base}{token}"
    logger.info(ADMIN_RESET_MESSAGE, message, reset_link)
    return reset_link


async def bootstrap_system(
    user_name: str | None = None, org_name: str | None = None
) -> dict:
    """
    Bootstrap the entire system with default data.

    Args:
        user_name: Display name for the admin user (default: "Admin")
        org_name: Display name for the organization (default: "Organization")

    Returns:
        dict: Contains information about created entities and reset link
    """
    # Create permission first - will fail if already exists
    perm0 = Permission(id="auth:admin", display_name="Master Admin")
    await globals.db.instance.create_permission(perm0)

    org = Org(uuid7.create(), org_name or "Organization")
    await globals.db.instance.create_organization(org)

    # After creation, org.permissions now includes the auto-created org admin permission
    # Allow this org to grant global admin explicitly
    await globals.db.instance.add_permission_to_organization(str(org.uuid), perm0.id)

    # Create an Administration role granting both org and global admin
    # Compose permissions for Administration role: global admin + org admin auto-perm
    role = Role(
        uuid7.create(),
        org.uuid,
        "Administration",
        permissions=[perm0.id, *org.permissions],
    )
    await globals.db.instance.create_role(role)

    user = User(
        uuid=uuid7.create(),
        display_name=user_name or "Admin",
        role_uuid=role.uuid,
        created_at=datetime.now(),
        visits=0,
    )
    await globals.db.instance.create_user(user)

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
        permission_orgs = await globals.db.instance.get_permission_organizations(
            "auth:admin"
        )

        if not permission_orgs:
            return False

        # Get users from the first organization with admin permission
        org_users = await globals.db.instance.get_organization_users(
            str(permission_orgs[0].uuid)
        )
        admin_users = [user for user, role in org_users if role == "Administration"]

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


async def bootstrap_if_needed(
    default_admin: str | None = None, default_org: str | None = None
) -> bool:
    """
    Check if system needs bootstrapping and perform it if necessary.

    Args:
        default_admin: Display name for the admin user
        default_org: Display name for the organization

    Returns:
        bool: True if bootstrapping was performed, False if system was already set up
    """
    try:
        # Check if the admin permission exists - if it does, system is already bootstrapped
        await globals.db.instance.get_permission("auth:admin")
        # Permission exists, system is already bootstrapped
        # Check if admin needs credentials (only for already-bootstrapped systems)
        await check_admin_credentials()
        return False
    except Exception:
        # Permission doesn't exist, need to bootstrap
        pass

    # No admin permission found, need to bootstrap
    # Bootstrap creates the admin user AND the reset link, so no need to check credentials after
    await bootstrap_system(default_admin, default_org)
    return True


# CLI interface
async def main():
    """Main CLI entry point for bootstrapping."""
    import argparse

    # Configure logging for CLI usage
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

    parser = argparse.ArgumentParser(
        description="Bootstrap passkey authentication system"
    )
    parser.add_argument(
        "--user-name",
        default=None,
        help="Name for the admin user (default: Admin)",
    )
    parser.add_argument(
        "--org-name",
        default=None,
        help="Name for the organization (default: Organization)",
    )

    args = parser.parse_args()

    await globals.init(default_admin=args.user_name, default_org=args.org_name)


if __name__ == "__main__":
    asyncio.run(main())
