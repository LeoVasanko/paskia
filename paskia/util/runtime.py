"""Runtime serve configuration (process-global parameters only).

Domain configuration lives in the database (``Config.domains``); the
``PASKIA_CONFIG`` environment variable only carries the effective listen
endpoints so that child processes (uvicorn reload / workers) can derive
site URLs the same way the parent did.
"""

import os
from functools import lru_cache

import msgspec


class ServeConfig(msgspec.Struct):
    """Process-global serve parameters."""

    listen: list[str] | None = None


@lru_cache(maxsize=1)
def _load() -> ServeConfig | None:
    raw = os.getenv("PASKIA_CONFIG")
    if not raw:
        return None
    return msgspec.json.decode(raw.encode(), type=ServeConfig)


def serve_config() -> ServeConfig | None:
    """Return cached serve configuration loaded from PASKIA_CONFIG."""
    return _load()


def clear_cache() -> None:
    """Clear cached serve configuration; next serve_config() reloads."""
    _load.cache_clear()
