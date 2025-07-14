"""
Device addition API handlers for WebAuthn authentication.

This module provides endpoints for authenticated users to:
- Generate device addition links with human-readable tokens
- Validate device addition tokens
- Add new passkeys to existing accounts via tokens
"""

from datetime import datetime, timedelta

from fastapi import Request

from ..db import sql
from ..util.passphrase import generate
from .session_manager import get_current_user


async def create_device_addition_link(request: Request) -> dict:
    """Create a device addition link for the authenticated user."""
    try:
        # Require authentication
        user = await get_current_user(request)
        if not user:
            return {"error": "Authentication required"}

        # Generate a human-readable token
        token = generate(n=4, sep=".")  # e.g., "able-ocean-forest-dawn"

        # Create reset token in database
        await sql.create_reset_token(user.user_id, token)

        # Generate the device addition link with pretty URL
        addition_link = f"{request.headers.get('origin', '')}/auth/{token}"

        return {
            "status": "success",
            "message": "Device addition link generated successfully",
            "addition_link": addition_link,
            "expires_in_hours": 24,
        }

    except Exception as e:
        return {"error": f"Failed to create device addition link: {str(e)}"}


async def validate_device_addition_token(request: Request) -> dict:
    """Validate a device addition token and return user info."""
    try:
        body = await request.json()
        token = body.get("token")

        if not token:
            return {"error": "Device addition token is required"}

        # Get reset token
        reset_token = await sql.get_reset_token(token)
        if not reset_token:
            return {"error": "Invalid or expired device addition token"}

        # Check if token is expired (24 hours)
        expiry_time = reset_token.created_at + timedelta(hours=24)
        if datetime.now() > expiry_time:
            return {"error": "Device addition token has expired"}

        # Get user info
        user = await sql.get_user_by_id(reset_token.user_id)

        return {
            "status": "success",
            "valid": True,
            "user_id": str(user.user_id),
            "user_name": user.user_name,
            "token": token,
        }

    except Exception as e:
        return {"error": f"Failed to validate device addition token: {str(e)}"}


async def use_device_addition_token(token: str) -> dict:
    """Delete a device addition token after successful use."""
    try:
        # Get reset token first to validate it exists and is not expired
        reset_token = await sql.get_reset_token(token)
        if not reset_token:
            return {"error": "Invalid or expired device addition token"}

        # Check if token is expired (24 hours)
        expiry_time = reset_token.created_at + timedelta(hours=24)
        if datetime.now() > expiry_time:
            return {"error": "Device addition token has expired"}

        # Delete the token (it's now used)
        await sql.delete_reset_token(token)

        return {
            "status": "success",
            "message": "Device addition token used successfully",
        }

    except Exception as e:
        return {"error": f"Failed to use device addition token: {str(e)}"}
