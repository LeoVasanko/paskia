from dataclasses import dataclass
from datetime import timedelta

# Shared configuration constants for session management.
SESSION_LIFETIME = timedelta(hours=24)

# Lifetime for reset links created by admins
RESET_LIFETIME = timedelta(days=14)


@dataclass
class PaskiaConfig:
    """Runtime configuration for the Paskia authentication server."""

    rp_id: str
    rp_name: str | None
    origins: list[str] | None
    auth_host: str | None
    site_url: str  # Base URL without trailing path (e.g. https://example.com)
    site_path: str  # Path to auth UI: "/" if auth_host, else "/auth/"
    # Listen address (one of host:port or uds)
    host: str | None = None
    port: int | None = None
    uds: str | None = None
