"""
Session management for WebAuthn authentication.

This module provides session management functionality including:
- Getting current user from session cookies
- Setting and clearing HTTP-only cookies
- Session validation and token handling
"""

from typing import Optional
from uuid import UUID

from fastapi import Request, Response

from .db import User, get_user_by_id
from .jwt_manager import validate_session_token

COOKIE_NAME = "session_token"
COOKIE_MAX_AGE = 86400  # 24 hours


async def get_current_user(request: Request) -> Optional[User]:
    """Get the current user from the session cookie."""
    session_token = request.cookies.get(COOKIE_NAME)
    if not session_token:
        return None

    token_data = validate_session_token(session_token)
    if not token_data:
        return None

    try:
        user = await get_user_by_id(token_data["user_id"])
        return user
    except Exception:
        return None


def set_session_cookie(response: Response, session_token: str) -> None:
    """Set the session token as an HTTP-only cookie."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=session_token,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
    )


def clear_session_cookie(response: Response) -> None:
    """Clear the session cookie."""
    response.delete_cookie(key=COOKIE_NAME)


def get_session_token_from_request(request: Request) -> Optional[str]:
    """Extract session token from request cookies."""
    return request.cookies.get(COOKIE_NAME)


async def validate_session_from_request(request: Request) -> Optional[dict]:
    """Validate session token from request and return token data."""
    session_token = get_session_token_from_request(request)
    if not session_token:
        return None

    return validate_session_token(session_token)


async def get_session_token_from_auth_header_or_body(request: Request) -> Optional[str]:
    """Extract session token from Authorization header or request body."""
    # Try to get token from Authorization header first
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer " prefix

    # Try to get from request body
    try:
        body = await request.json()
        return body.get("session_token")
    except Exception:
        return None


async def get_user_from_cookie_string(cookie_header: str) -> Optional[UUID]:
    """Parse cookie header and return user ID if valid session exists."""
    if not cookie_header:
        return None

    # Parse cookies from header (simple implementation)
    cookies = {}
    for cookie in cookie_header.split(";"):
        cookie = cookie.strip()
        if "=" in cookie:
            name, value = cookie.split("=", 1)
            cookies[name] = value

    session_token = cookies.get(COOKIE_NAME)
    if not session_token:
        return None

    token_data = validate_session_token(session_token)
    if not token_data:
        return None

    return token_data["user_id"]
