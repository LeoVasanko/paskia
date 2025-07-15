"""
Device addition API handlers for WebAuthn authentication.

This module provides endpoints for authenticated users to:
- Generate device addition links with human-readable tokens
- Validate device addition tokens
- Add new passkeys to existing accounts via tokens
"""

from datetime import datetime, timedelta

from fastapi import FastAPI, Path, Request
from fastapi.responses import RedirectResponse

from ..db import sql
from ..util.passphrase import generate
from .session import get_current_user


def register_reset_routes(app: FastAPI):
    """Register all device addition/reset routes on the FastAPI app."""

    @app.post("/auth/create-device-link")
    async def api_create_device_link(request: Request):
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

    @app.get("/auth/device-session-check")
    async def check_device_session(request: Request):
        """Check if the current session is for device addition."""
        from .session import is_device_addition_session

        is_device_session = await is_device_addition_session(request)
        return {"device_addition_session": is_device_session}

    @app.get("/auth/{passphrase}")
    async def reset_authentication(
        passphrase: str = Path(pattern=r"^\w+(\.\w+){2,}$"),
    ):
        try:
            # Get reset token to validate it exists and get user_id
            reset_token = await sql.get_reset_token(passphrase)
            if not reset_token:
                # Token doesn't exist, redirect to home
                return RedirectResponse(url="/", status_code=303)

            # Check if token is expired (24 hours)
            expiry_time = reset_token.created_at + timedelta(hours=24)
            if datetime.now() > expiry_time:
                # Token expired, clean it up and redirect to home
                await sql.delete_reset_token(passphrase)
                return RedirectResponse(url="/", status_code=303)

            # Create a device addition session token for the user
            from ..util.jwt import create_device_addition_token

            session_token = create_device_addition_token(reset_token.user_id)

            # Create response and set session cookie
            response = RedirectResponse(url="/auth/", status_code=303)
            from .session import set_session_cookie

            set_session_cookie(response, session_token)

            return response

        except Exception:
            # On any error, redirect to home
            return RedirectResponse(url="/", status_code=303)


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
