"""
SQL to JSON migration module for Paskia.

This module contains the legacy SQL database implementation and migration tools
for converting from the old SQLite database to the new JSONL format.

Usage:
    python -m paskia.migrate --sql sqlite+aiosqlite:///paskia.sqlite --json paskia.jsonl

Or via the CLI entry point (if installed):
    paskia-migrate --sql sqlite+aiosqlite:///paskia.sqlite --json paskia.jsonl
"""

import argparse
import asyncio
import re
from datetime import UTC, datetime
from uuid import UUID

import base64url
import uuid7
from sqlalchemy import select

from paskia.authsession import EXPIRES
from paskia.db.jsonl import JsonlStore
from paskia.db.structs import (
    DB,
    Credential,
    Org,
    Permission,
    Role,
    Session,
    User,
)

from .sql import (
    DB as SQLDB,
)
from .sql import (
    CredentialModel,
    SessionModel,
    UserModel,
)

# Re-export for convenience
__all__ = ["migrate_from_sql", "main", "SQLDB"]

# Default paths
SQL_DB_DEFAULT = "sqlite+aiosqlite:///paskia.sqlite"
JSON_DB_DEFAULT = "paskia.jsonl"


async def migrate_from_sql(
    sql_db_path: str = SQL_DB_DEFAULT,
    json_db_path: str = JSON_DB_DEFAULT,
) -> None:
    """Migrate data from SQL database to JSON format.

    Args:
        sql_db_path: SQLAlchemy connection string for the source SQL database
        json_db_path: Path for the destination JSONL file
    """
    # Initialize source SQL database
    sql_db = SQLDB(sql_db_path)
    await sql_db.init_db()

    # Initialize destination JSON database (fresh, don't load existing)
    db = DB()
    store = JsonlStore(db, json_db_path)
    db._store = store

    print(f"Migrating from {sql_db_path} to {json_db_path}...")

    # Build all data directly without saving (we'll save once at the end)
    # Track old permission ID -> new scope mapping for migration
    # Also track org-specific admin permissions to consolidate
    old_org_admin_pattern = re.compile(r"^auth:org:([0-9a-f-]+)$", re.IGNORECASE)
    org_admin_uuids = set()  # org UUIDs that had org-specific admin permissions

    # First pass: identify org-specific admin permissions
    permissions = await sql_db.list_permissions()
    for perm in permissions:
        match = old_org_admin_pattern.match(perm.id)
        if match:
            org_admin_uuids.add(match.group(1).lower())

    # Migrate permissions with UUID keys and scope field
    # Always create exactly one common auth:org:admin permission for all org admin needs
    org_admin_perm_uuid: UUID = uuid7.create()
    org_admin_perm = Permission(
        scope="auth:org:admin",
        display_name="Org Admin",
        orgs={},
    )
    org_admin_perm.uuid = org_admin_perm_uuid
    db.permissions[org_admin_perm_uuid] = org_admin_perm

    # Mapping from old permission ID to new permission UUID
    perm_id_to_uuid: dict[str, UUID] = {}

    for perm in permissions:
        # Skip old org-specific admin permissions (auth:org:{uuid}) - they map to auth:org:admin
        match = old_org_admin_pattern.match(perm.id)
        if match:
            perm_id_to_uuid[perm.id] = org_admin_perm_uuid
            continue

        # Skip if this is already auth:org:admin - we created one above
        if perm.id == "auth:org:admin":
            perm_id_to_uuid[perm.id] = org_admin_perm_uuid
            continue

        # Regular permission - create with UUID key
        perm_uuid: UUID = uuid7.create()
        new_perm = Permission(
            scope=perm.id,  # Old ID becomes the scope
            display_name=perm.display_name,
            orgs={},
        )
        new_perm.uuid = perm_uuid
        db.permissions[perm_uuid] = new_perm
        perm_id_to_uuid[perm.id] = perm_uuid
    print(
        f"  Migrated {len(permissions)} permissions (with {len(org_admin_uuids)} org-specific admins consolidated to auth:org:admin)"
    )

    # Migrate organizations
    orgs = await sql_db.list_organizations()
    for org in orgs:
        org_key: UUID = org.uuid
        new_org = Org(display_name=org.display_name)
        new_org.uuid = org_key
        db.orgs[org_key] = new_org
        # Update permissions to allow this org to grant them (by UUID)
        for old_perm_id in org.permissions:
            perm_uuid = perm_id_to_uuid.get(old_perm_id)
            if perm_uuid and perm_uuid in db.permissions:
                db.permissions[perm_uuid].orgs[org_key] = True
        # Ensure every org can grant auth:org:admin
        db.permissions[org_admin_perm_uuid].orgs[org_key] = True
    print(f"  Migrated {len(orgs)} organizations")

    # Migrate roles - convert old permission IDs to UUIDs
    role_count = 0
    for org in orgs:
        for role in org.roles:
            role_key: UUID = role.uuid
            # Convert old permission IDs to UUIDs
            new_permissions: dict[UUID, bool] = {}
            for old_perm_id in role.permissions or []:
                perm_uuid = perm_id_to_uuid.get(old_perm_id)
                if perm_uuid:
                    new_permissions[perm_uuid] = True
            new_role = Role(
                org_uuid=role.org_uuid,
                display_name=role.display_name,
                permissions=new_permissions,
            )
            new_role.uuid = role_key
            db.roles[role_key] = new_role
            role_count += 1
    print(f"  Migrated {role_count} roles")

    # Migrate users
    async with sql_db.session() as session:
        result = await session.execute(select(UserModel))
        user_models = result.scalars().all()
        for um in user_models:
            legacy_user = um.as_dataclass()
            user_key: UUID = legacy_user.uuid
            new_user = User(
                display_name=legacy_user.display_name,
                role_uuid=legacy_user.role_uuid,
                created_at=legacy_user.created_at or datetime.now(UTC),
                last_seen=legacy_user.last_seen,
                visits=legacy_user.visits,
            )
            new_user.uuid = user_key
            db.users[user_key] = new_user
        print(f"  Migrated {len(user_models)} users")

    # Migrate credentials
    async with sql_db.session() as session:
        result = await session.execute(select(CredentialModel))
        cred_models = result.scalars().all()
        for cm in cred_models:
            legacy_cred = cm.as_dataclass()
            cred_key: UUID = legacy_cred.uuid
            new_cred = Credential(
                credential_id=legacy_cred.credential_id,
                user_uuid=legacy_cred.user_uuid,
                aaguid=legacy_cred.aaguid,
                public_key=legacy_cred.public_key,
                sign_count=legacy_cred.sign_count,
                created_at=legacy_cred.created_at,
                last_used=legacy_cred.last_used,
                last_verified=legacy_cred.last_verified,
            )
            new_cred.uuid = cred_key
            db.credentials[cred_key] = new_cred
        print(f"  Migrated {len(cred_models)} credentials")

    # Migrate sessions
    # Old format: b"sess" + 12 bytes -> New format: base64url string (16 chars)
    async with sql_db.session() as session:
        result = await session.execute(select(SessionModel))
        session_models = result.scalars().all()
        for sm in session_models:
            sess = sm.as_dataclass()
            old_key: bytes = sess.key
            # Strip b"sess" prefix and encode remaining 12 bytes as base64url
            if old_key.startswith(b"sess"):
                session_key = base64url.enc(old_key[4:])
            else:
                # Already in new format or unknown - try to use as-is
                session_key = base64url.enc(old_key[:12])
            db.sessions[session_key] = Session(
                user_uuid=sess.user_uuid,
                credential_uuid=sess.credential_uuid,
                host=sess.host,
                ip=sess.ip,
                user_agent=sess.user_agent,
                expiry=sess.renewed + EXPIRES,  # Convert renewed to expiry
            )
        print(f"  Migrated {len(session_models)} sessions")

    # Reset tokens are not migrated - they will expire naturally
    # and users can generate new ones as needed
    print("  Reset tokens dropped (not migrated)")

    # Queue and flush all changes using the transaction mechanism
    with db.transaction("migrate:sql"):
        pass  # All data already added to _data, transaction commits on exit

    await store.flush()

    print("Migration complete!")


def main():
    """CLI entry point for migration."""

    parser = argparse.ArgumentParser(
        description="Migrate Paskia database from SQL to JSON"
    )
    parser.add_argument(
        "--sql",
        default=SQL_DB_DEFAULT,
        help=f"Source SQL database connection string (default: {SQL_DB_DEFAULT})",
    )
    parser.add_argument(
        "--json",
        default=JSON_DB_DEFAULT,
        help=f"Destination JSONL file path (default: {JSON_DB_DEFAULT})",
    )
    args = parser.parse_args()

    asyncio.run(migrate_from_sql(args.sql, args.json))


if __name__ == "__main__":
    main()
