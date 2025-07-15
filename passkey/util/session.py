"""
Database session management for WebAuthn authentication.

This module provides session management using database tokens instead of JWT tokens.
Session tokens are stored in the database and validated on each request.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import Request

from ..db import sql


def get_client_info(request: Request) -> dict:
    """Extract client information from FastAPI request and return as dict."""
    # Get client IP (handle X-Forwarded-For for proxies)
    # Get user agent
    return {
        "client_ip": request.client.host if request.client else "",
        "user_agent": request.headers.get("user-agent", "")[:500],
    }


def get_client_info_from_websocket(ws) -> dict:
    """Extract client information from WebSocket connection and return as dict."""
    # Get client IP from WebSocket
    client_ip = None
    if hasattr(ws, "client") and ws.client:
        client_ip = ws.client.host

    # Check for forwarded headers
    if hasattr(ws, "headers"):
        forwarded_for = ws.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

    # Get user agent from WebSocket headers
    user_agent = None
    if hasattr(ws, "headers"):
        user_agent = ws.headers.get("user-agent")
        # Truncate user agent if too long
        if user_agent and len(user_agent) > 500:  # Keep some margin
            user_agent = user_agent[:500]

    return {
        "client_ip": client_ip,
        "user_agent": user_agent,
        "timestamp": datetime.now().isoformat(),
        "connection_type": "websocket",
    }


async def create_session_token(
    user_id: UUID, credential_id: bytes, info: dict | None = None
) -> str:
    """Create a session token for a user."""
    return await sql.create_session_by_credential_id(user_id, credential_id, None, info)


async def validate_session_token(token: str) -> Optional[dict]:
    """Validate a session token."""
    session_data = await sql.get_session(token)
    if not session_data:
        return None

    return {
        "user_id": session_data["user_id"],
        "credential_id": session_data["credential_id"],
        "created_at": session_data["created_at"],
    }


async def refresh_session_token(token: str) -> Optional[str]:
    """Refresh a session token."""
    return await sql.refresh_session(token)


async def delete_session_token(token: str) -> None:
    """Delete a session token."""
    await sql.delete_session(token)


async def logout_session(token: str) -> None:
    """Log out a user by deleting their session token."""
    await sql.delete_session(token)
