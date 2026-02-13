"""
Database schema migrations.

Migrations are applied during database load based on the version field.
Each migration should be idempotent and only run when needed.
"""

from collections.abc import Awaitable, Callable


def migrate_v1(d: dict, **kwargs) -> None:
    """Remove Org.created_at fields."""
    for org_data in d["orgs"].values():
        org_data.pop("created_at", None)


def migrate_v2(d: dict, *, rp_id: str = "localhost") -> None:
    """Add config field if missing."""
    if "config" not in d:
        d["config"] = {"rp_id": rp_id}


def migrate_v3(d: dict, **kwargs) -> None:
    """Ensure all users have visits field."""
    for user_data in d["users"].values():
        user_data.setdefault("visits", 0)


migrations = sorted(
    [f for n, f in globals().items() if n.startswith("migrate_v")],
    key=lambda f: int(f.__name__.removeprefix("migrate_v")),
)

DBVER = len(migrations)  # Used by bootstrap to set initial version


async def apply_all_migrations(
    data_dict: dict,
    current_version: int,
    persist: Callable[[str, int, dict], Awaitable[None]],
    *,
    rp_id: str = "localhost",
) -> None:
    while current_version < DBVER:
        migrations[current_version](data_dict, rp_id=rp_id)
        current_version += 1
        await persist(f"migrate:v{current_version}", current_version, data_dict)
