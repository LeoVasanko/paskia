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


def _bytes_to_str(b: bytes | None) -> str | None:
    """Convert bytes to base64url string."""
    if b is None:
        return None
    return base64url.enc(b)


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

    from paskia.db.json import (
        DB as JSONDB,
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

    # Initialize destination JSON database
    json_db = JSONDB(json_db_path)
    json_db.load()

    print(f"Migrating from {sql_db_path} to {json_db_path}...")

    # Build all data directly without saving (we'll save once at the end)
    with json_db._lock:
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
        org_admin_perm_uuid = str(uuid7.create())
        json_db._data.permissions[org_admin_perm_uuid] = _PermissionData(
            scope="auth:org:admin",
            display_name="Organization Admin",
            orgs={},
        )

        # Mapping from old permission ID to new scope
        perm_id_to_scope: dict[str, str] = {}

        for perm in permissions:
            # Skip old org-specific admin permissions (auth:org:{uuid}) - they map to auth:org:admin
            match = old_org_admin_pattern.match(perm.id)
            if match:
                perm_id_to_scope[perm.id] = "auth:org:admin"
                continue

            # Skip if this is already auth:org:admin - we created one above
            if perm.id == "auth:org:admin":
                perm_id_to_scope[perm.id] = "auth:org:admin"
                continue

            # Regular permission - create with UUID key
            perm_uuid = str(uuid7.create())
            json_db._data.permissions[perm_uuid] = _PermissionData(
                scope=perm.id,  # Old ID becomes the scope
                display_name=perm.display_name,
                orgs={},
            )
            perm_id_to_scope[perm.id] = perm.id  # Scope same as old ID
        print(
            f"  Migrated {len(permissions)} permissions (with {len(org_admin_uuids)} org-specific admins consolidated to auth:org:admin)"
        )

        # Migrate organizations
        orgs = await sql_db.list_organizations()
        for org in orgs:
            key = str(org.uuid)
            json_db._data.orgs[key] = _OrgData(
                display_name=org.display_name,
            )
            # Update permissions to allow this org to grant them (by scope)
            for old_perm_id in org.permissions:
                new_scope = perm_id_to_scope.get(old_perm_id, old_perm_id)
                # Find permission with this scope and add org
                for pid, p in json_db._data.permissions.items():
                    if p.scope == new_scope:
                        p.orgs[key] = True
                        break
            # Ensure every org can grant auth:org:admin
            json_db._data.permissions[org_admin_perm_uuid].orgs[key] = True
        print(f"  Migrated {len(orgs)} organizations")

        # Migrate roles - convert old permission IDs to scopes
        role_count = 0
        for org in orgs:
            for role in org.roles:
                key = str(role.uuid)
                # Convert old permission IDs to scopes
                new_permissions = {}
                for old_perm_id in role.permissions or []:
                    new_scope = perm_id_to_scope.get(old_perm_id, old_perm_id)
                    new_permissions[new_scope] = True
                json_db._data.roles[key] = _RoleData(
                    org=str(role.org_uuid),
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
                key = str(user.uuid)
                json_db._data.users[key] = _UserData(
                    display_name=user.display_name,
                    role=str(user.role_uuid),
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
                key = str(cred.uuid)
                json_db._data.credentials[key] = _CredentialData(
                    credential_id=cred.credential_id,
                    user=str(cred.user_uuid),
                    aaguid=str(cred.aaguid),
                    public_key=cred.public_key,
                    sign_count=cred.sign_count,
                    created_at=cred.created_at,
                    last_used=cred.last_used,
                    last_verified=cred.last_verified,
                )
            print(f"  Migrated {len(cred_models)} credentials")

        # Migrate sessions
        async with sql_db.session() as session:
            result = await session.execute(select(SessionModel))
            session_models = result.scalars().all()
            for sm in session_models:
                sess = sm.as_dataclass()
                key_b64 = _bytes_to_str(sess.key)
                json_db._data.sessions[key_b64] = _SessionData(
                    user=str(sess.user_uuid),
                    credential=str(sess.credential_uuid),
                    host=sess.host,
                    ip=sess.ip,
                    user_agent=sess.user_agent,
                    expiry=sess.renewed + EXPIRES,  # Convert renewed to expiry
                )
            print(f"  Migrated {len(session_models)} sessions")

        # Migrate reset tokens
        async with sql_db.session() as session:
            result = await session.execute(select(ResetTokenModel))
            token_models = result.scalars().all()
            for tm in token_models:
                token = tm.as_dataclass()
                key_b64 = _bytes_to_str(token.key)
                json_db._data.reset_tokens[key_b64] = _ResetTokenData(
                    user=str(token.user_uuid),
                    expiry=token.expiry,
                    token_type=token.token_type,
                )
            print(f"  Migrated {len(token_models)} reset tokens")

        # Queue and flush all changes with actor "migrate"
        json_db._current_actor = "migrate"
        json_db._queue_change()
        json_db.flush()

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
