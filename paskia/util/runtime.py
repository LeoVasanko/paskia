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
def _load_config() -> RuntimeConfig | None:
    """Load RuntimeConfig from PASKIA_CONFIG env var."""
    config_json = os.getenv("PASKIA_CONFIG")
    if not config_json:
        return None

    return msgspec.json.decode(config_json.encode(), type=RuntimeConfig)


def config() -> RuntimeConfig | None:
    """Return cached runtime config loaded from PASKIA_CONFIG."""
    return _load_config()


def clear_config_cache() -> None:
    """Clear cached runtime config; next config() call reloads from env."""
    _load_config.cache_clear()


def update_runtime_config(new_config: Config) -> None:
    """Update the runtime configuration with a new Config and refresh the cache."""
    current_runtime = config()
    if not current_runtime:
        return  # No runtime config to update

    # Recompute site_url and site_path based on new config
    old_auth_host = current_runtime.config.auth_host
    if new_config.auth_host:
        site_url, site_path = new_config.auth_host, "/"
    else:
        site_path = "/auth/"
        # Never derive site_url from a just-removed auth host
        origins = [o for o in (new_config.origins or []) if o != old_auth_host]
        if origins:
            site_url = origins[0]
        elif current_runtime.site_url != old_auth_host:
            # Keep current site_url if it wasn't derived from the removed auth host
            site_url = current_runtime.site_url
        else:
            site_url = f"https://{new_config.rp_id}"

    new_runtime = RuntimeConfig(
        config=new_config,
        site_url=site_url,
        site_path=site_path,
        save=current_runtime.save,
    )
    os.environ["PASKIA_CONFIG"] = msgspec.json.encode(new_runtime).decode()

    # Clear the cache so next access loads the updated config
    clear_config_cache()
