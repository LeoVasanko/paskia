"""Runtime configuration utilities."""

import os
from functools import lru_cache

import msgspec

from paskia.db.structs import Config


class RuntimeConfig(msgspec.Struct):
    """Runtime configuration for the Paskia authentication server.

    Wraps the db Config (CLI/stored settings) with computed runtime fields.
    Serialized to PASKIA_CONFIG env var as JSON via msgspec.
    """

    config: Config  # CLI/stored configuration to persist
    site_url: str  # Base URL without trailing path (e.g. https://example.com)
    site_path: str  # Path to auth UI: "/" if auth_host, else "/auth/"
    save: bool = False  # Whether to persist config to database


@lru_cache(maxsize=1)
def _load_config() -> "RuntimeConfig | None":
    """Load RuntimeConfig from PASKIA_CONFIG env var."""
    config_json = os.getenv("PASKIA_CONFIG")
    if not config_json:
        return None

    return msgspec.json.decode(config_json.encode(), type=RuntimeConfig)
