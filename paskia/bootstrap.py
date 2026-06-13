"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.

The actual database seeding is performed by the module-level kanta bootstrap
callback defined in :mod:`paskia.db.bootstrap` and registered during
:func:`paskia.db.lifecycle.init`.
"""

import logging

from paskia import authsession, db
from paskia.db.bootstrap import log_reset_link
from paskia.db.structs import Config

logger = logging.getLogger(__name__)


def _configure_logger() -> None:
    if logger.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


_configure_logger()


def _log_reset_link(passphrase: str, message: str | None = None) -> str:
    """Log a reset link message and return the URL."""
    return log_reset_link(passphrase, message)


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
    Check if admin needs credentials and create a reset link if needed.

    Database bootstrapping itself is now handled automatically during
    ``db.init()`` via the registered kanta bootstrap callback. This function
    remains as a post-init hook for credential checks.

    Args:
        config: Kept for backwards compatibility; config is now applied during
            ``db.init()``.

    Returns:
        bool: Always returns False (bootstrapping is performed during init).
    """
    await check_admin_credentials()
    return False
