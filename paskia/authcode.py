"""
Authorization code management for OIDC and cookie exchange flows.

Codes are short-lived (60 seconds) and stored in-memory only.
Two separate stores maintain full isolation between OIDC and cookie flows.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import UTC, datetime, timedelta

import msgspec

_logger = logging.getLogger(__name__)

# Auth codes expire after this duration
AUTH_CODE_LIFETIME = timedelta(seconds=60)


class OIDCCode(msgspec.Struct):
    """An OIDC authorization code pending token exchange.

    PKCE uses S256 only when provided (verified at token exchange).
    """

    session_key: str
    created: datetime
    redirect_uri: str
    scope: str
    nonce: str | None = None
    code_challenge: str | None = None


class CookieCode(msgspec.Struct):
    """A cookie exchange code for setting session cookie after WebSocket auth."""

    session_key: str
    created: datetime


# Separate stores for each code type
oidc_codes: dict[str, OIDCCode] = {}
cookie_codes: dict[str, CookieCode] = {}

# Background cleanup task
_cleanup_task: asyncio.Task | None = None


async def start():
    """Start the cleanup background task."""
    global _cleanup_task
    if _cleanup_task is None:
        _cleanup_task = asyncio.create_task(_cleanup_loop())


async def stop():
    """Stop the cleanup background task."""
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
        try:
            await _cleanup_task
        except asyncio.CancelledError:
            pass
        _cleanup_task = None


async def _cleanup_loop():
    while True:
        try:
            await asyncio.sleep(30)  # Check every 30 seconds
            _cleanup_expired()
        except asyncio.CancelledError:
            break
        except Exception:
            _logger.exception("Error in auth code cleanup loop")


def _cleanup_expired():
    oldest = datetime.now(UTC) - AUTH_CODE_LIFETIME
    for code, auth_code in list(oidc_codes.items()):
        if auth_code.created < oldest:
            del oidc_codes[code]
    for code, auth_code in list(cookie_codes.items()):
        if auth_code.created < oldest:
            del cookie_codes[code]


def store_oidc(code: OIDCCode) -> str:
    """Store an OIDC authorization code and return the code string."""
    token = secrets.token_urlsafe(12)
    oidc_codes[token] = code
    return token


def consume_oidc(token: str) -> OIDCCode | None:
    """Consume an OIDC code, returning it if valid. Atomic removal."""
    return oidc_codes.pop(token, None)


def store_cookie(code: CookieCode) -> str:
    """Store a cookie exchange code and return the code string."""
    token = secrets.token_urlsafe(12)
    cookie_codes[token] = code
    return token


def consume_cookie(token: str) -> CookieCode | None:
    """Consume a cookie exchange code, returning it if valid. Atomic removal."""
    return cookie_codes.pop(token, None)
