"""Utilities for host validation and origin determination."""

from ..globals import passkey as global_passkey


def effective_origin(scheme: str, host: str | None, rp_id: str) -> str:
    """Determine the effective origin for a request.

    Uses the provided host if it's compatible with the relying party ID,
    otherwise falls back to the configured origin.

    Args:
        scheme: The URL scheme (e.g. "https")
        host: The host header value (e.g. "example.com" or "sub.example.com:8080")
        rp_id: The relying party ID (e.g. "example.com")

    Returns:
        The effective origin URL to use
    """
    if host:
        hostname = host.split(":")[0]  # Remove port if present
        if hostname == rp_id or hostname.endswith(f".{rp_id}"):
            return f"{scheme}://{host}"
    return global_passkey.instance.origin
