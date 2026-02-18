"""
FastAPI-specific session management for WebAuthn authentication.

This module provides FastAPI-specific session management functionality:
- Extracting client information from FastAPI requests
- Setting and clearing HTTP-only cookies via FastAPI Response objects

Generic session management functions have been moved to authsession.py
"""

from ipaddress import IPv4Address, IPv6Address

from fastapi import Cookie, Request, Response, WebSocket

from paskia.authsession import EXPIRES

AUTH_COOKIE_NAME = "__Host-paskia"
AUTH_COOKIE = Cookie(None, alias=AUTH_COOKIE_NAME)


def normalize_ip(ip: str) -> str:
    """Normalize IP address, stripping brackets and validating format.

    Proxies may pass IPv6 in brackets like [::1] or with zone IDs.
    IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) are converted to plain IPv4.
    Returns empty string for invalid addresses.
    """
    if not ip:
        return ""
    # Strip brackets that some proxies add around IPv6
    ip = ip.strip("[]")
    # Strip zone ID (e.g., fe80::1%eth0)
    if "%" in ip:
        ip = ip.split("%")[0]
    try:
        # Validate and normalize
        if ":" in ip:
            addr = IPv6Address(ip)
            # Convert IPv4-mapped addresses to plain IPv4
            if addr.ipv4_mapped:
                return str(addr.ipv4_mapped)
            return str(addr)
        return str(IPv4Address(ip))
    except ValueError:
        return ip  # Return as-is if not a valid IP (could be hostname)


def get_client_ip(request: Request | WebSocket) -> str:
    """Get client IP from request, normalized."""
    if not request.client:
        return ""
    return normalize_ip(request.client.host)


def infodict(request: Request | WebSocket, type: str) -> dict:
    """Extract client information from request."""
    return {
        "ip": get_client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:500],
        "session_type": type,
    }


def set_session_cookie(response: Response, token: str) -> None:
    """Set the session token as an HTTP-only cookie."""
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=token,
        max_age=int(EXPIRES.total_seconds()),
        httponly=True,
        secure=True,
        path="/",
        samesite="strict",
    )


def clear_session_cookie(response: Response) -> None:
    # FastAPI's delete_cookie does not set the secure attribute
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value="",
        max_age=0,
        expires=0,
        httponly=True,
        secure=True,
        path="/",
        samesite="strict",
    )
