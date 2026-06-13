"""
Database schema migrations.

Migrations are applied during database load based on the version field.
Each migration should be idempotent and only run when needed.
"""

import base64

from kanta import Kanta

from paskia.util.crypto import secret_key


def migrate_v1(d: dict) -> None:
    """Remove Org.created_at fields."""
    for org_data in d["orgs"].values():
        org_data.pop("created_at", None)


def migrate_v2(d: dict, kanta: Kanta) -> None:
    """Add config field if missing."""
    if "config" not in d:
        d["config"] = {"rp_id": kanta.ctx.rp_id}


def migrate_v3(d: dict) -> None:
    """Ensure all users have visits field."""
    for user_data in d["users"].values():
        user_data.setdefault("visits", 0)


def migrate_v4(d: dict) -> None:
    """OpenID Connect support and hardened session keys."""
    # Session keys changed to hashes, drop old sessions
    d["sessions"] = {}
    # Create OIDC structure with a generated new key
    d["oidc"] = {
        "clients": {},
        "key": base64.standard_b64encode(secret_key()).decode(),
    }


def migrate_v5(d: dict) -> None:
    """Convert config.listen from str to list[str] if needed."""
    listen = d["config"].get("listen")
    if listen and isinstance(listen, str):
        d["config"]["listen"] = [listen]
