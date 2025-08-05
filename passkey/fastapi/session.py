"""
FastAPI-specific session management for WebAuthn authentication.

This module provides FastAPI-specific session management functionality:
- Extracting client information from FastAPI requests
- Setting and clearing HTTP-only cookies via FastAPI Response objects

Generic session management functions have been moved to authsession.py
"""

from fastapi import Request, Response, WebSocket

from ..authsession import EXPIRES


def infodict(request: Request | WebSocket, type: str) -> dict:
    """Extract client information from request."""
    return {
        "ip": request.client.host if request.client else "",
        "user_agent": request.headers.get("user-agent", "")[:500],
        "type": type,
    }


def set_session_cookie(response: Response, token: str) -> None:
    """Set the session token as an HTTP-only cookie."""
    response.set_cookie(
        key="auth",
        value=token,
        max_age=int(EXPIRES.total_seconds()),
        httponly=True,
        secure=True,
        path="/auth/",
    )
