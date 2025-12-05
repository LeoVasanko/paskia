"""Utilities for determining the auth UI host and base URLs."""

import json
import os
from functools import lru_cache
from urllib.parse import urlparse, urlsplit

from paskia.globals import passkey as global_passkey


def _default_origin_scheme() -> str:
    """Get the default scheme from configured origins, or fallback to https."""
    allowed = global_passkey.instance.allowed_origins
    if allowed:
        # Pick any origin from the set
        origin_url = urlparse(next(iter(allowed)))
        return origin_url.scheme or "https"
    return "https"


@lru_cache(maxsize=1)
def _load_config() -> tuple[str | None, str] | None:
    """Load auth_host from PASKIA_CONFIG JSON, falling back to PASKIA_AUTH_HOST."""
    # Try PASKIA_CONFIG first (set by CLI)
    config_json = os.getenv("PASKIA_CONFIG")
    if config_json:
        config = json.loads(config_json)
        raw = config["auth_host"]  # Always present, may be None
    else:
        # Fallback for external usage (e.g., PASKIA_AUTH_HOST set directly)
        raw = os.getenv("PASKIA_AUTH_HOST")

    if not raw:
        return None
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    netloc = parsed.netloc or parsed.path
    if not netloc:
        return None
    return (parsed.scheme or None, netloc.strip("/"))


def configured_auth_host() -> str | None:
    cfg = _load_config()
    return cfg[1] if cfg else None


def is_root_mode() -> bool:
    return _load_config() is not None


def ui_base_path() -> str:
    return "/" if is_root_mode() else "/auth/"


def auth_site_base_url(scheme: str | None = None, host: str | None = None) -> str:
    cfg = _load_config()
    if cfg:
        cfg_scheme, cfg_host = cfg
        scheme_to_use = cfg_scheme or scheme or _default_origin_scheme()
        netloc = cfg_host
    else:
        if host:
            scheme_to_use = scheme or _default_origin_scheme()
            netloc = host.strip("/")
        else:
            # Use the first allowed origin, or fallback to rp_id
            allowed = global_passkey.instance.allowed_origins
            if allowed:
                origin = allowed[0].rstrip("/")
                return f"{origin}{ui_base_path()}"
            # Fallback: construct from rp_id
            rp_id = global_passkey.instance.rp_id
            return f"https://{rp_id}{ui_base_path()}"

    base = f"{scheme_to_use}://{netloc}".rstrip("/")
    path = ui_base_path().lstrip("/")
    return f"{base}/{path}" if path else f"{base}/"


def reset_link_url(
    token: str, scheme: str | None = None, host: str | None = None
) -> str:
    base = auth_site_base_url(scheme, host)
    return f"{base}{token}"


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
