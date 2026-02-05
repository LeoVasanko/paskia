"""Utilities for determining the auth UI host and base URLs."""

import json
import os
from functools import lru_cache
from urllib.parse import urlparse, urlsplit


@lru_cache(maxsize=1)
def _load_config() -> dict:
    """Load PASKIA_CONFIG JSON."""
    config_json = os.getenv("PASKIA_CONFIG")
    if not config_json:
        return {}
    return json.loads(config_json)


def is_root_mode() -> bool:
    return _load_config().get("auth_host") is not None


def dedicated_auth_host() -> str | None:
    """Return configured auth_host netloc, or None."""
    auth_host = _load_config().get("auth_host")
    if not auth_host:
        return None

    parsed = urlparse(auth_host if "://" in auth_host else f"//{auth_host}")
    return parsed.netloc or parsed.path or None


def ui_base_path() -> str:
    return "/" if is_root_mode() else "/auth/"


def auth_site_url() -> str:
    """Return the base URL for the auth site UI (computed at startup)."""
    cfg = _load_config()
    return cfg.get("site_url", "https://localhost") + cfg.get("site_path", "/auth/")


def reset_link_url(token: str) -> str:
    """Generate a reset link URL for the given token."""
    return f"{auth_site_url()}{token}"


def normalize_origin(origin: str) -> str:
    """Normalize an origin URL by adding https:// if no scheme is present."""
    if "://" not in origin:
        return f"https://{origin}"
    return origin


def reload_config() -> None:
    _load_config.cache_clear()


def normalize_host(raw_host: str | None) -> str | None:
    """Normalize a Host header, stripping port numbers for consistent matching."""
    if not raw_host:
        return None
    candidate = raw_host.strip()
    if not candidate:
        return None
    # urlsplit to parse (add // for scheme-less); prefer netloc to retain port.
    parsed = urlsplit(candidate if "//" in candidate else f"//{candidate}")
    netloc = parsed.netloc or parsed.path or ""
    # Handle IPv6 addresses: [ipv6]:port or [ipv6]
    if netloc.startswith("["):
        if "]" in netloc:
            host_part, _, _ = netloc.partition("]")
            netloc = host_part.strip("[]")
    else:
        # Strip port from host:port
        netloc = netloc.rsplit(":", 1)[0]
    return netloc.lower() or None
