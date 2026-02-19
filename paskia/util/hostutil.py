"""Utilities for determining the auth UI host and base URLs."""

from urllib.parse import urlparse, urlsplit

from paskia.util.runtime import _load_config


def _cfg():
    return _load_config()


def is_root_mode() -> bool:
    cfg = _cfg()
    return cfg is not None and cfg.config.auth_host is not None


def dedicated_auth_host() -> str | None:
    """Return configured auth_host netloc, or None."""
    cfg = _cfg()
    auth_host = cfg.config.auth_host if cfg else None
    if not auth_host:
        return None

    parsed = urlparse(auth_host if "://" in auth_host else f"//{auth_host}")
    return parsed.netloc or parsed.path or None


def ui_base_path() -> str:
    return "/" if is_root_mode() else "/auth/"


def auth_site_url() -> str:
    """Return the base URL for the auth site UI (computed at startup)."""
    cfg = _cfg()
    if cfg:
        return cfg.site_url + cfg.site_path
    return "https://localhost/auth/"


def reset_link_url(token: str) -> str:
    """Generate a reset link URL for the given token."""
    return f"{auth_site_url()}{token}"


def normalize_origin(origin: str) -> str:
    """Normalize an origin URL by adding https:// if no scheme is present, removing trailing slashes."""
    if "://" not in origin:
        return f"https://{origin}"
    return origin.rstrip("/")


def is_subdomain(sub: str, domain: str) -> bool:
    """Check if sub is a subdomain of domain (or equal)."""
    sub_parts = sub.lower().split(".")
    domain_parts = domain.lower().split(".")
    if len(sub_parts) < len(domain_parts):
        return False
    return sub_parts[-len(domain_parts) :] == domain_parts


def validate_auth_host(auth_host: str, rp_id: str) -> None:
    """Validate that auth_host is a subdomain of rp_id.

    Raises ValueError on invalid auth_host.
    """
    parsed = urlparse(auth_host if "://" in auth_host else f"//{auth_host}")
    host = parsed.hostname or parsed.path
    if not host:
        raise ValueError(f"Invalid auth-host: '{auth_host}'")
    if not is_subdomain(host, rp_id):
        raise ValueError(
            f"auth-host '{auth_host}' is not a subdomain of rp-id '{rp_id}'"
        )


def normalize_auth_host_and_origins(
    auth_host: str | None, origins: list[str] | None
) -> tuple[str | None, list[str] | None]:
    """Normalize auth_host and origins, matching CLI startup behavior.

    - Adds https:// to auth_host if no scheme present, strips trailing slashes
    - Validates auth_host is a well-formed subdomain (caller provides rp_id via validate_auth_host)
    - Inserts auth_host as first origin if both are specified and not already present
    - Deduplicates origins while preserving order
    """
    if auth_host:
        if "://" not in auth_host:
            auth_host = f"https://{auth_host}"
        auth_host = auth_host.rstrip("/")
        if origins is not None and auth_host not in origins:
            origins.insert(0, auth_host)
    if origins:
        origins = list(dict.fromkeys(origins))
    return auth_host, origins


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


def format_endpoint(ep: dict) -> str:
    """Format an endpoint dict to a listen string (e.g. 'unix:/path' or 'host:port')."""
    if uds := ep.get("uds"):
        return f"unix:{uds}"
    host = ep["host"]
    port = ep["port"]
    # Bracket IPv6 addresses
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}"
