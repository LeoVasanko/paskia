"""
Database schema migrations.

Migrations are applied during database load based on the version field.
Each migration should be idempotent and only run when needed.
"""

import logging

_logger = logging.getLogger(__name__)


def apply_migrations(data_dict: dict) -> bool:
    """Apply any pending schema migrations to the database dictionary.

    Args:
        data_dict: The raw database dictionary loaded from JSONL

    Returns:
        True if any migrations were applied, False otherwise
    """
    db_version = data_dict.get("v", 0)
    migrated = False

    if db_version == 0:
        # Migration v0 -> v1: Remove created_at from orgs (field removed from schema)
        if "orgs" in data_dict:
            for org_data in data_dict["orgs"].values():
                org_data.pop("created_at", None)
        data_dict["v"] = 1
        migrated = True
        _logger.info("Applied schema migration: v0 -> v1 (removed org.created_at)")

    if db_version < 2:
        # Migration v1 -> v2: Convert null ip/user_agent to empty strings in sessions
        if "sessions" in data_dict:
            for session_data in data_dict["sessions"].values():
                if session_data.get("ip") is None:
                    session_data["ip"] = ""
                if session_data.get("user_agent") is None:
                    session_data["user_agent"] = ""
                if session_data.get("host") is None:
                    session_data["host"] = ""
        data_dict["v"] = 2
        migrated = True
        _logger.info(
            "Applied schema migration: v1 -> v2 (null session fields -> empty strings)"
        )

    return migrated
