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
    from sqlalchemy import select

    from paskia.db.json import (
        DB as JSONDB,
    )
    from paskia.db.json import (
        CredentialData,
        OrgData,
        PermissionData,
        ResetTokenData,
        RoleData,
        SessionData,
        UserData,
    )

    # Initialize source SQL database
    sql_db = SQLDB(sql_db_path)
    await sql_db.init_db()

    # Initialize destination JSON database
    json_db = JSONDB(json_db_path)
    await json_db.init_db()

    print(f"Migrating from {sql_db_path} to {json_db_path}...")

    # Build all data directly without saving (we'll save once at the end)
    async with json_db._lock:
        # Migrate permissions
        permissions = await sql_db.list_permissions()
        for perm in permissions:
            json_db._data.permissions[perm.id] = PermissionData(
                display_name=perm.display_name,
                orgs={},
            )
        print(f"  Migrated {len(permissions)} permissions")

        # Migrate organizations
        orgs = await sql_db.list_organizations()
        for org in orgs:
            key = str(org.uuid)
            json_db._data.orgs[key] = OrgData(
                display_name=org.display_name,
            )
            # Update permissions to allow this org to grant them
            for perm_id in org.permissions:
                if perm_id in json_db._data.permissions:
                    json_db._data.permissions[perm_id].orgs[key] = True
        print(f"  Migrated {len(orgs)} organizations")

        # Migrate roles
        role_count = 0
        for org in orgs:
            for role in org.roles:
                key = str(role.uuid)
                json_db._data.roles[key] = RoleData(
                    org=str(role.org_uuid),
                    display_name=role.display_name,
                    permissions={p: True for p in role.permissions}
                    if role.permissions
                    else {},
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
                json_db._data.users[key] = UserData(
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
                json_db._data.credentials[key] = CredentialData(
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
                json_db._data.sessions[key_b64] = SessionData(
                    user=str(sess.user_uuid),
                    credential=str(sess.credential_uuid),
                    host=sess.host,
                    ip=sess.ip,
                    user_agent=sess.user_agent,
                    renewed=sess.renewed,
                )
            print(f"  Migrated {len(session_models)} sessions")

        # Migrate reset tokens
        async with sql_db.session() as session:
            result = await session.execute(select(ResetTokenModel))
            token_models = result.scalars().all()
            for tm in token_models:
                token = tm.as_dataclass()
                key_b64 = _bytes_to_str(token.key)
                json_db._data.reset_tokens[key_b64] = ResetTokenData(
                    user=str(token.user_uuid),
                    expiry=token.expiry,
                    token_type=token.token_type,
                )
            print(f"  Migrated {len(token_models)} reset tokens")

        # Save all changes as a single diff with actor "migrate"
        # Start from empty {} so diff shows pure insertions
        json_db._previous_builtins = {}
        await json_db._save(actor="migrate")

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
