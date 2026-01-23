"""
Database module for WebAuthn passkey authentication.

This module re-exports the JSONL database types and implementation.
All data types are msgspec Structs for efficient serialization.
Database methods are synchronous (no await needed).

Usage:
    from paskia import db

    # Access the database instance (after init)
    db.create_session(...)
    user = db.get_user_by_uuid(uuid)
"""

from paskia.db.json import (
    Credential,
    DB,
    Org,
    Permission,
    ResetToken,
    Role,
    Session,
    SessionContext,
    User,
    init,
    start_background,
    stop_background,
    start_cleanup,
    stop_cleanup,
)
import paskia.db.json as _json_module


class _DBProxy:
    """Proxy that forwards attribute access to the global DB instance.

    This allows using `db.method()` directly instead of `db.get_db().method()`.
    """

    def __getattr__(self, name: str):
        db = _json_module._db
        if db is None:
            raise RuntimeError("Database not initialized. Call init() first.")
        return getattr(db, name)


# Module-level proxy for direct access
_proxy = _DBProxy()


def __getattr__(name: str):
    """Module-level __getattr__ to forward DB method calls."""
    if name in __all__:
        raise AttributeError(name)
    return getattr(_proxy, name)


__all__ = [
    "Credential",
    "DB",
    "Org",
    "Permission",
    "ResetToken",
    "Role",
    "Session",
    "SessionContext",
    "User",
    "init",
    "start_background",
    "stop_background",
    "start_cleanup",
    "stop_cleanup",
]
