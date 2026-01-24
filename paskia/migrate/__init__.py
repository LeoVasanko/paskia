"""
SQL to JSON migration module for Paskia.

This module contains the legacy SQL database implementation and migration tools
for converting from the old SQLite database to the new JSONL format.

Usage:
    python -m paskia.migrate --sql sqlite+aiosqlite:///paskia.sqlite --json paskia.jsonl

Or via the CLI entry point (if installed):
    paskia-migrate --sql sqlite+aiosqlite:///paskia.sqlite --json paskia.jsonl
"""

import asyncio
from datetime import datetime, timezone
from uuid import UUID

import base64url

from paskia.authsession import EXPIRES

from .sql import (
    DB as SQLDB,
)
from .sql import (
    CredentialModel,
    ResetTokenModel,
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
    # Import here to avoid circular imports and to not require JSON db at import time
    import re

    import uuid7
    from sqlalchemy import select

    from paskia.db.operations import DB as JSONDB
    from paskia.db.structs import (
        _CredentialData,
        _OrgData,
        _PermissionData,
        _ResetTokenData,
        _RoleData,
        _SessionData,
        _UserData,
    )

    # Initialize source SQL database
    sql_db = SQLDB(sql_db_path)
    await sql_db.init_db()

    # Initialize destination JSON database (fresh, don't load existing)
    json_db = JSONDB(json_db_path)
    # Don't call json_db.load() - we want a fresh database, not to load existing

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
    json_db._data.permissions[org_admin_perm_uuid] = _PermissionData(
        scope="auth:org:admin",
        display_name="Org Admin",
        orgs={},
    )

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
        json_db._data.permissions[perm_uuid] = _PermissionData(
            scope=perm.id,  # Old ID becomes the scope
            display_name=perm.display_name,
            orgs={},
        )
        perm_id_to_uuid[perm.id] = perm_uuid
    print(
        f"  Migrated {len(permissions)} permissions (with {len(org_admin_uuids)} org-specific admins consolidated to auth:org:admin)"
    )

    # Migrate organizations
    orgs = await sql_db.list_organizations()
    for org in orgs:
        org_key: UUID = org.uuid
        json_db._data.orgs[org_key] = _OrgData(
            display_name=org.display_name,
        )
        # Update permissions to allow this org to grant them (by UUID)
        for old_perm_id in org.permissions:
            perm_uuid = perm_id_to_uuid.get(old_perm_id)
            if perm_uuid and perm_uuid in json_db._data.permissions:
                json_db._data.permissions[perm_uuid].orgs[org_key] = True
        # Ensure every org can grant auth:org:admin
        json_db._data.permissions[org_admin_perm_uuid].orgs[org_key] = True
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
            json_db._data.roles[role_key] = _RoleData(
                org=role.org_uuid,
                display_name=role.display_name,
                permissions=new_permissions,
            )
            role_count += 1
    print(f"  Migrated {role_count} roles")

    # Migrate users
    async with sql_db.session() as session:
        result = await session.execute(select(UserModel))
        user_models = result.scalars().all()
        for um in user_models:
            user = um.as_dataclass()
            user_key: UUID = user.uuid
            json_db._data.users[user_key] = _UserData(
                display_name=user.display_name,
                role=user.role_uuid,
                created_at=user.created_at or datetime.now(timezone.utc),
                last_seen=user.last_seen,
                visits=user.visits,
            )
        print(f"  Migrated {len(user_models)} users")

    # Migrate credentials
    async with sql_db.session() as session:
        result = await session.execute(select(CredentialModel))
        cred_models = result.scalars().all()
        for cm in cred_models:
            cred = cm.as_dataclass()
            cred_key: UUID = cred.uuid
            json_db._data.credentials[cred_key] = _CredentialData(
                credential_id=cred.credential_id,
                user=cred.user_uuid,
                aaguid=cred.aaguid,
                public_key=cred.public_key,
                sign_count=cred.sign_count,
                created_at=cred.created_at,
                last_used=cred.last_used,
                last_verified=cred.last_verified,
            )
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
            json_db._data.sessions[session_key] = _SessionData(
                user=sess.user_uuid,
                credential=sess.credential_uuid,
                host=sess.host,
                ip=sess.ip,
                user_agent=sess.user_agent,
                expiry=sess.renewed + EXPIRES,  # Convert renewed to expiry
            )
        print(f"  Migrated {len(session_models)} sessions")

    # Migrate reset tokens
    # Old format: b"rset" + 16 bytes hash -> New format: 9 bytes (truncated hash)
    async with sql_db.session() as session:
        result = await session.execute(select(ResetTokenModel))
        token_models = result.scalars().all()
        for tm in token_models:
            token = tm.as_dataclass()
            old_key: bytes = token.key
            # Strip b"rset" prefix and take first 9 bytes of hash
            if old_key.startswith(b"rset"):
                token_key = old_key[4:13]  # 9 bytes after prefix
            else:
                # Already in new format or unknown - truncate to 9 bytes
                token_key = old_key[:9]
            json_db._data.reset_tokens[token_key] = _ResetTokenData(
                user=token.user_uuid,
                expiry=token.expiry,
                token_type=token.token_type,
            )
        print(f"  Migrated {len(token_models)} reset tokens")

    # Queue and flush all changes with actor "migrate"
    json_db._current_actor = "migrate"
    json_db._queue_change()
    from paskia.db.jsonl import flush_changes

    await flush_changes(json_db.db_path, json_db._pending_changes)

    print("Migration complete!")


def main():
    """CLI entry point for migration."""
    import argparse

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
