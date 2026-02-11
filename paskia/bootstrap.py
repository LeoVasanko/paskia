"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.
"""

import logging

from paskia import authsession, db
from paskia.db.structs import Config
from paskia.util import hostutil

logger = logging.getLogger(__name__)

# Shared log message template for admin reset links
ADMIN_RESET_MESSAGE = """
👤 Admin  %s
   - Use this link to register a Passkey for the admin user!
"""


def _log_reset_link(passphrase: str, message: str | None = None) -> str:
    """Log a reset link message and return the URL."""
    reset_link = hostutil.reset_link_url(passphrase)
    if message:
        logger.info(message)
    logger.info(ADMIN_RESET_MESSAGE, reset_link)
    return reset_link


async def bootstrap_system(config: Config | None = None) -> None:
    """
    Bootstrap the entire system with default data.

    Uses db.bootstrap() which performs all operations in a single transaction.
    The transaction log will show a single "bootstrap" action with all changes.

    Args:
        config: Configuration to store (rp_id, rp_name, origins, etc.)
    """
    # Call the single-transaction bootstrap function
    reset_passphrase = db.bootstrap(config=config)

    # Log the reset link (this is separate from the transaction log)
    _log_reset_link(reset_passphrase, "✅ Bootstrap completed!")


async def check_admin_credentials() -> bool:
    """
    Check if the admin user needs credentials and create a reset link if needed.

    Returns:
        bool: True if a reset link was created, False if admin already has credentials
    """
    try:
        # Find the auth:admin permission
        p = next(
            (p for p in db.data().permissions.values() if p.scope == "auth:admin"), None
        )
        if not p:
            return False

        perm_uuid = p.uuid

        # Find all roles that have the auth:admin permission
        admin_roles = [
            r for r in db.data().roles.values() if perm_uuid in r.permissions
        ]

        # Collect all users from those roles
        admin_users = []
        for role in admin_roles:
            admin_users.extend(role.users)

        if not admin_users:
            return False

        # Check first admin user for credentials
        admin_user = admin_users[0]

        if not admin_user.credential_ids:
            # Admin exists but has no credentials, create reset link
            logger.info("⚠️  Admin user has no credentials!")

            expiry = authsession.reset_expires()
            token = db.create_reset_token(
                user_uuid=admin_user.uuid,
                expiry=expiry,
                token_type="admin registration",
            )
            _log_reset_link(token)
            return True

        return False

    except Exception:
        return False


async def bootstrap_if_needed(config: Config | None = None) -> bool:
    """
    Check if system needs bootstrapping and perform it if necessary.

    Args:
        config: Configuration to store during bootstrap (rp_id, rp_name, origins, etc.)

    Returns:
        bool: True if bootstrapping was performed, False if system was already set up
    """
    # Check if the admin permission exists - if it does, system is already bootstrapped
    if any(p.scope == "auth:admin" for p in db.data().permissions.values()):
        # Permission exists, system is already bootstrapped
        # Check if admin needs credentials (only for already-bootstrapped systems)
        await check_admin_credentials()
        return False

    # No admin permission found, need to bootstrap
    # Bootstrap creates the admin user AND the reset link, so no need to check credentials after
    await bootstrap_system(config=config)
    return True
