"""Runtime serve configuration (process-global parameters only).

Domain configuration lives in the database (``Config.domains``); the
``PASKIA_CONFIG`` environment variable only carries the effective listen
endpoints and whether to persist them, so that child processes (uvicorn
reload / workers) derive site URLs the same way the parent did. The CLI
entry point mutates the bound object before ``server.run()`` calls
``teleport()`` to pass it on.
"""

import msgspec
from fastapi_vue import env


class ServeConfig(msgspec.Struct):
    """Process-global serve parameters."""

    listen: list[str] | None = None
    save: bool = False  # Persist listen to the stored config on startup


def serve_config() -> ServeConfig:
    """Return the serve configuration bound to PASKIA_CONFIG."""
    return env(ServeConfig, name="CONFIG")


def clear_cache() -> None:
    """Drop the bound configuration; next serve_config() re-decodes."""
    env._bindings.pop("CONFIG", None)  # noqa: SLF001
