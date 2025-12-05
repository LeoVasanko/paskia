"""Utilities for determining the auth UI host and base URLs."""

import os
from functools import lru_cache
from urllib.parse import urlparse, urlsplit

from paskia.globals import passkey as global_passkey

_AUTH_HOST_ENV = "PASKIA_AUTH_HOST"


def _default_origin_scheme() -> str:
    origin_url = urlparse(global_passkey.instance.origin)
    return origin_url.scheme or "https"


@lru_cache(maxsize=1)
def _load_config() -> tuple[str | None, str] | None:
    raw = os.getenv(_AUTH_HOST_ENV)
    if not raw:
        return None
    candidate = raw.strip()
    if not candidate:
        return None
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
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
            origin = global_passkey.instance.origin.rstrip("/")
            return f"{origin}{ui_base_path()}"

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
