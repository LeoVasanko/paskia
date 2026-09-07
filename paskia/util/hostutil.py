"""Utilities for host/origin normalization and validation."""

import re
from urllib.parse import urlparse, urlsplit

_RP_ID_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)


def validate_rp_id(rp_id: str) -> None:
    """Validate that rp_id is a valid domain name (or localhost)."""
    if not rp_id:
        raise ValueError("rp_id cannot be empty")
    if rp_id == "localhost":
        return
    if not _RP_ID_RE.match(rp_id):
        raise ValueError(f"rp_id '{rp_id}' is not a valid domain name")


def is_valid_hostname(hostname: str) -> bool:
    """Check hostname shape: dot-separated alphanumeric/hyphen labels —
    no empty labels, so no leading/trailing or double dots ('.localhost',
    'localhost.', 'a..b.com' are all malformed)."""
    return bool(_RP_ID_RE.match(hostname))


def is_wildcard_pattern(value: str) -> bool:
    """Check whether an origins entry is a wildcard pattern like
    '*.example.com' (one subdomain level) or '**.example.com' (the base
    domain and any depth of subdomains)."""
    return value.startswith("*.") or value.startswith("**.")


def wildcard_base(pattern: str) -> str | None:
    """Base domain of a wildcard pattern; None if not a wildcard."""
    if pattern.startswith("**."):
        return pattern[3:].rstrip(".") or None
    if pattern.startswith("*."):
        return pattern[2:].rstrip(".") or None
    return None


def normalize_origin(origin: str) -> str:
    """Normalize an origin URL by adding https:// if no scheme is present, removing trailing slashes.

    Wildcard patterns ('*.example.com', '**.example.com') pass through
    unchanged — they are allow-list entries, not concrete origins.
    """
    if is_wildcard_pattern(origin):
        return origin.rstrip("/.")
    if "://" not in origin:
        return f"https://{origin}"
    return origin.rstrip("/")


def origin_hostname(origin: str) -> str | None:
    """Extract the lowercase hostname from an origin URL, if well-formed.

    For wildcard patterns the base domain is returned.
    """
    if base := wildcard_base(origin):
        return base.lower()
    return urlparse(origin).hostname


def is_subdomain(sub: str, domain: str) -> bool:
    """Check if sub is a subdomain of domain (or equal)."""
    sub_parts = sub.lower().split(".")
    domain_parts = domain.lower().split(".")
    if len(sub_parts) < len(domain_parts):
        return False
    return sub_parts[-len(domain_parts) :] == domain_parts


def auth_host_netloc(auth_host: str) -> str | None:
    """Return the host[:port] part of a configured auth host URL."""
    parsed = urlparse(auth_host if "://" in auth_host else f"//{auth_host}")
    return parsed.netloc or parsed.path or None


def normalize_host(raw_host: str | None) -> str | None:
    """Normalize a Host header, stripping port numbers and trailing dots."""
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
    return netloc.lower().rstrip(".") or None


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
