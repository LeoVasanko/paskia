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
    
    return migrated
