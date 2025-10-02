"""Utilities for determining the auth UI host and base URLs."""

import os
from functools import lru_cache
from urllib.parse import urlparse

from ..globals import passkey as global_passkey

_AUTH_HOST_ENV = "PASSKEY_AUTH_HOST"


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


def _format_base_url(scheme: str, netloc: str) -> str:
    scheme_part = scheme or _default_origin_scheme()
    base = f"{scheme_part}://{netloc}"
    return base if base.endswith("/") else f"{base}/"


def auth_site_base_url(scheme: str | None = None, host: str | None = None) -> str:
    cfg = _load_config()
    if cfg:
        cfg_scheme, cfg_host = cfg
        scheme_to_use = cfg_scheme or scheme or _default_origin_scheme()
        return _format_base_url(scheme_to_use, cfg_host)

    if host:
        scheme_to_use = scheme or _default_origin_scheme()
        return _format_base_url(scheme_to_use, host.strip("/"))

    origin = global_passkey.instance.origin.rstrip("/")
    return f"{origin}/auth/"


def reload_config() -> None:
    _load_config.cache_clear()
