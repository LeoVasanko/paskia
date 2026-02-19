"""
Database schema migrations.

Migrations are applied during database load based on the version field.
Each migration should be idempotent and only run when needed.
"""

import base64
from collections.abc import Awaitable, Callable

import msgspec

from paskia.util.crypto import secret_key


class MigrationCtx(msgspec.Struct):
    """Context passed to each migration function."""

    rp_id: str


def migrate_v1(d: dict, ctx: MigrationCtx) -> None:
    """Remove Org.created_at fields."""
    for org_data in d["orgs"].values():
        org_data.pop("created_at", None)


def migrate_v2(d: dict, ctx: MigrationCtx) -> None:
    """Add config field if missing."""
    if "config" not in d:
        d["config"] = {"rp_id": ctx.rp_id}


def migrate_v3(d: dict, ctx: MigrationCtx) -> None:
    """Ensure all users have visits field."""
    for user_data in d["users"].values():
        user_data.setdefault("visits", 0)


def migrate_v4(d: dict, ctx: MigrationCtx) -> None:
    """OpenID Connect support and hardened session keys."""
    # Session keys changed to hashes, drop old sessions
    d["sessions"] = {}
    # Create OIDC structure with a generated new key
    d["oidc"] = {"clients": {}, "key": base64.standard_b64encode(secret_key()).decode()}


migrations = sorted(
    [f for n, f in globals().items() if n.startswith("migrate_v")],
    key=lambda f: int(f.__name__.removeprefix("migrate_v")),
)

DBVER = len(migrations)  # Used by bootstrap to set initial version


def apply_migrations_readonly(
    data_dict: dict,
    current_version: int,
    ctx: MigrationCtx,
) -> int:
    """Apply migration functions in-place without persistence.

    Returns the new version after all migrations.
    """
    while current_version < DBVER:
        migrations[current_version](data_dict, ctx)
        current_version += 1
    return current_version


async def apply_all_migrations(
    data_dict: dict,
    current_version: int,
    persist: Callable[[str, int, dict], Awaitable[None]],
    ctx: MigrationCtx,
) -> None:
    while current_version < DBVER:
        migrations[current_version](data_dict, ctx)
        current_version += 1
        await persist(f"migrate:v{current_version}", current_version, data_dict)
