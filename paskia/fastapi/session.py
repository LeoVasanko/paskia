"""
FastAPI-specific session management for WebAuthn authentication.

This module provides FastAPI-specific session management functionality:
- Extracting client information from FastAPI requests
- Setting and clearing HTTP-only cookies via FastAPI Response objects

Generic session management functions have been moved to authsession.py
"""

from fastapi import Cookie, Request, Response, WebSocket

from paskia.authsession import EXPIRES

AUTH_COOKIE_NAME = "__Host-paskia"
AUTH_COOKIE = Cookie(None, alias=AUTH_COOKIE_NAME)


def infodict(request: Request | WebSocket, type: str) -> dict:
    """Extract client information from request."""
    return {
        "ip": request.client.host if request.client else "",
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
        samesite="lax",
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
        samesite="lax",
    )
