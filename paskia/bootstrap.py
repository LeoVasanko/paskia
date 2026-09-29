"""
Bootstrap module for passkey authentication system.

The initial database seeding (admin user, organization, permissions,
registration reset token) is performed by ``paskia init`` via
:func:`paskia.db.bootstrap.bootstrap`. This module provides the serve-time
check that re-prints a registration link when the admin user still has no
passkey on any configured domain.
"""

import logging

from paskia import authsession, db, domains
from paskia.db.bootstrap import log_reset_link

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


async def check_admin_credentials() -> bool:
    """
    Check if the admin user needs credentials and create a reset link if needed.

    With global users, the admin may hold passkeys under any configured
    domain — the check passes if the admin has a credential for at least
    one of them. Otherwise a reset link is printed for the first domain
    (sorted by rp-id).

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

        # Check first admin user for credentials on any configured domain
        admin_user = admin_users[0]
        reg = domains.registry()
        # Remote domains hold their credentials on the remote instance
        configured = sorted(d.rp_id for d in reg.domains if d.remote is None)
        if not configured:
            return False

        if not any(admin_user.credential_ids_for(rp_id) for rp_id in configured):
            # Admin exists but has no credential on any domain
            target = reg.get(configured[0])
            logger.info("⚠️  Admin user has no credentials on %s!", target.rp_id)

            expiry = authsession.reset_expires()
            token = db.create_reset_token(
                user_uuid=admin_user.uuid,
                expiry=expiry,
                token_type="admin registration",
            )
            log_reset_link(target.reset_link_url(token))
            return True

        return False

    except Exception:
        return False


async def bootstrap_if_needed() -> bool:
    """Run the serve-time admin credential check.

    Returns:
        bool: Always returns False (bootstrapping is performed by ``paskia init``).
    """
    await check_admin_credentials()
    return False
