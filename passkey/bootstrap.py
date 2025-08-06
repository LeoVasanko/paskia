"""
Bootstrap module for passkey authentication system.

This module handles initial system setup when a new database is created,
including creating default admin user, organization, permissions, and
generating a reset link for initial admin setup.
"""

from datetime import datetime

import uuid7

from .authsession import expires
from .db import Org, Permission, User, db
from .util import passphrase, tokens


class BootstrapManager:
    """Manages system bootstrapping operations."""

    def __init__(self):
        self.admin_uuid = uuid7.create()
        self.org_uuid = uuid7.create()

    async def create_default_organization(self) -> Org:
        """Create the default organization."""
        org = Org(
            id=str(self.org_uuid),  # Use UUID string as required by database
            options={
                "display_name": "Organization",
                "description": "Default organization for passkey authentication system",
                "created_at": datetime.now().isoformat(),
            },
        )
        await db.instance.create_organization(org)
        return org

    async def create_admin_permission(self) -> Permission:
        """Create the admin permission."""
        permission = Permission(
            id="auth/admin", display_name="Authentication Administration"
        )
        await db.instance.create_permission(permission)
        return permission

    async def create_default_admin_user(self) -> User:
        """Create the default admin user."""
        user = User(
            uuid=self.admin_uuid,
            display_name="Admin",
            org_uuid=self.org_uuid,
            role="Admin",
            created_at=datetime.now(),
            visits=0,
        )
        await db.instance.create_user(user)
        return user

    async def assign_permissions_to_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        """Assign permission to organization."""
        await db.instance.add_permission_to_organization(org_id, permission_id)

    async def generate_admin_reset_link(self) -> str:
        """Generate a reset link for the admin user to register their first passkey."""
        # Generate a human-readable passphrase token
        token = passphrase.generate()  # e.g., "cross.rotate.yin.note.evoke"

        # Create a reset session for the admin user
        await db.instance.create_session(
            user_uuid=self.admin_uuid,
            key=tokens.reset_key(token),
            expires=expires(),
            info={
                "type": "bootstrap_reset",
                "description": "Initial admin setup",
                "created_at": datetime.now().isoformat(),
            },
        )

        return token

    async def bootstrap_system(self) -> dict:
        """
        Bootstrap the entire system with default data.

        Returns:
            dict: Contains information about created entities and reset link
        """
        print("🚀 Bootstrapping passkey authentication system...")

        # Create default organization
        print("📂 Creating default organization...")
        org = await self.create_default_organization()

        # Create admin permission
        print("🔐 Creating admin permission...")
        permission = await self.create_admin_permission()

        # Create admin user
        print("👤 Creating admin user...")
        user = await self.create_default_admin_user()

        # Assign admin to organization
        print("🏢 Assigning admin to organization...")
        await db.instance.add_user_to_organization(
            user_uuid=self.admin_uuid, org_id=org.id, role="Admin"
        )

        # Assign permission to organization
        print("⚡ Assigning permissions to organization...")
        await self.assign_permissions_to_organization(org.id, permission.id)

        # Generate reset link for admin
        print("🔗 Generating admin setup link...")
        reset_token = await self.generate_admin_reset_link()

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
            "reset_token": reset_token,
        }

        print("\n✅ Bootstrap completed successfully!")
        print(f"\n🔑 Admin Reset Token: {reset_token}")
        print("\n📋 Use this token to set up the admin user's first passkey.")
        print("   The token will be valid for 24 hours.")
        print(f"\n👤 Admin User UUID: {user.uuid}")
        print(f"🏢 Organization: {org.options.get('display_name')} (ID: {org.id})")
        print(f"🔐 Permission: {permission.display_name} (ID: {permission.id})")

        return result


async def bootstrap_if_needed() -> bool:
    """
    Check if system needs bootstrapping and perform it if necessary.

    Returns:
        bool: True if bootstrapping was performed, False if system was already set up
    """
    try:
        # Try to get any organization to see if system is already bootstrapped
        # We'll use a more robust check by looking for existing users
        from sqlalchemy import select

        from .db.sql import DB, UserModel

        async with DB().session() as session:
            stmt = select(UserModel).limit(1)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()
            if user:
                print("ℹ️  System already bootstrapped (found existing users).")
                return False
    except Exception:
        pass

    # No users found, need to bootstrap
    manager = BootstrapManager()
    await manager.bootstrap_system()
    return True


async def force_bootstrap() -> dict:
    """
    Force bootstrap the system (useful for testing or resetting).

    Returns:
        dict: Bootstrap result information
    """
    manager = BootstrapManager()
    return await manager.bootstrap_system()


# CLI interface
async def main():
    """Main CLI entry point for bootstrapping."""
    import argparse

    from .db.sql import init

    parser = argparse.ArgumentParser(
        description="Bootstrap passkey authentication system"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force bootstrap even if system is already set up",
    )

    args = parser.parse_args()

    # Initialize database
    await init()

    if args.force:
        await force_bootstrap()
    else:
        await bootstrap_if_needed()


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
