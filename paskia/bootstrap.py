"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.
"""

import asyncio
import logging

from paskia import db
from paskia.util import hostutil

logger = logging.getLogger(__name__)

# Shared log message template for admin reset links
ADMIN_RESET_MESSAGE = """\
%s

👤 Admin  %s
   - Use this link to register a Passkey for the admin user!
"""


def _log_reset_link(message: str, passphrase: str) -> str:
    """Log a reset link message and return the URL."""
    reset_link = hostutil.reset_link_url(passphrase)
    logger.info(ADMIN_RESET_MESSAGE, message, reset_link)
    return reset_link


async def bootstrap_system() -> None:
    """
    Bootstrap the entire system with default data.

    Uses db.bootstrap() which performs all operations in a single transaction.
    The transaction log will show a single "bootstrap" action with all changes.
    """
    # Call the single-transaction bootstrap function
    reset_passphrase = db.bootstrap()

    # Log the reset link (this is separate from the transaction log)
    _log_reset_link("✅ Bootstrap completed!", reset_passphrase)


async def check_admin_credentials() -> bool:
    """
    Check if the admin user needs credentials and create a reset link if needed.

    Returns:
        bool: True if a reset link was created, False if admin already has credentials
    """
    try:
        # Get permission organizations to find admin users
        permission_orgs = db.get_permission_organizations("auth:admin")

        if not permission_orgs:
            return False

        # Get users from the first organization with admin permission
        org_users = db.get_organization_users(str(permission_orgs[0].uuid))
        admin_users = [user for user, role in org_users if role == "Administration"]

        if not admin_users:
            return False

        # Check first admin user for credentials
        admin_user = admin_users[0]
        credentials = db.get_credentials_by_user_uuid(admin_user.uuid)

        if not credentials:
            # Admin exists but has no credentials, create reset link
            from paskia import authsession
            from paskia.util import passphrase

            token = passphrase.generate()
            expiry = authsession.reset_expires()
            db.create_reset_token(
                user_uuid=admin_user.uuid,
                passphrase=token,
                expiry=expiry,
                token_type="admin registration",
            )
            _log_reset_link("⚠️  Admin user has no credentials!", token)
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
    # Check if the admin permission exists - if it does, system is already bootstrapped
    if db.get_permission_by_scope("auth:admin"):
        # Permission exists, system is already bootstrapped
        # Check if admin needs credentials (only for already-bootstrapped systems)
        await check_admin_credentials()
        return False

    # No admin permission found, need to bootstrap
    # Bootstrap creates the admin user AND the reset link, so no need to check credentials after
    await bootstrap_system()
    return True


# CLI interface
async def main():
    """Main CLI entry point for bootstrapping."""
    # Configure logging for CLI usage
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

    from paskia import globals

    await globals.init()


if __name__ == "__main__":
    asyncio.run(main())
