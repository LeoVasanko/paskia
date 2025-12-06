"""Utilities for determining the auth UI host and base URLs."""

import json
import os
from functools import lru_cache
from urllib.parse import urlparse, urlsplit

from paskia.globals import passkey as global_passkey


@lru_cache(maxsize=1)
def _load_config() -> tuple[str, str] | None:
    """Load auth_host from PASKIA_CONFIG JSON.

    Returns (scheme, netloc) tuple if configured, None otherwise.
    """
    config_json = os.getenv("PASKIA_CONFIG")
    if not config_json:
        return None
    config = json.loads(config_json)
    raw = config["auth_host"]  # Always present, may be None
    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    netloc = parsed.netloc or parsed.path
    if not netloc:
        return None
    return (parsed.scheme or "https", netloc.strip("/"))


def configured_auth_host() -> str | None:
    cfg = _load_config()
    return cfg[1] if cfg else None


def is_root_mode() -> bool:
    return _load_config() is not None


def ui_base_path() -> str:
    return "/" if is_root_mode() else "/auth/"


def auth_site_base_url() -> str:
    """Return the base URL for the auth site UI.

    If auth_host is configured (root mode), returns its URL.
    Otherwise, constructs URL from rp_id with /auth/ path.
    """
    cfg = _load_config()
    if cfg:
        scheme, netloc = cfg
        return f"{scheme}://{netloc}/"

    # Not in root mode: use rp_id with /auth/ path
    rp_id = global_passkey.instance.rp_id
    return f"https://{rp_id}/auth/"


def reset_link_url(token: str) -> str:
    return f"{auth_site_base_url()}{token}"


def reload_config() -> None:
    _load_config.cache_clear()


def normalize_host(raw_host: str | None) -> str | None:
    """Normalize a Host header preserving port (exact match required)."""
    if not raw_host:
        return None
    candidate = raw_host.strip()
    if not candidate:
        return None
    # urlsplit to parse (add // for scheme-less); prefer netloc to retain port.
    parsed = urlsplit(candidate if "//" in candidate else f"//{candidate}")
    netloc = parsed.netloc or parsed.path or ""
    # Strip IPv6 brackets around host part but retain port suffix.
    if netloc.startswith("["):
        # format: [ipv6]:port or [ipv6]
        if "]" in netloc:
            host_part, _, rest = netloc.partition("]")
            port_part = rest.lstrip(":")
            netloc = host_part.strip("[]") + (f":{port_part}" if port_part else "")
    return netloc.lower() or None
