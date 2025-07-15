"""
Device addition API handlers for WebAuthn authentication.

This module provides endpoints for authenticated users to:
- Generate device addition links with human-readable tokens
- Validate device addition tokens
- Add new passkeys to existing accounts via tokens
"""

from fastapi import FastAPI, Path, Request
from fastapi.responses import RedirectResponse

from ..db import sql
from ..util.passphrase import generate
from ..util.session import get_client_info
from .session import get_current_user, is_device_addition_session, set_session_cookie


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

            # Create session token in database with credential_id=None for device addition
            client_info = get_client_info(request)
            await sql.create_session(user.user_id, None, token, client_info)

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
        is_device_session = await is_device_addition_session(request)
        return {"device_addition_session": is_device_session}

    @app.get("/auth/{passphrase}")
    async def reset_authentication(
        request: Request,
        passphrase: str = Path(pattern=r"^\w+(\.\w+){2,}$"),
    ):
        try:
            # Get session token to validate it exists and get user_id
            session_data = await sql.get_session(passphrase)
            if not session_data:
                # Token doesn't exist, redirect to home
                return RedirectResponse(url="/", status_code=303)

            # Check if this is a device addition session (credential_id is None)
            if session_data["credential_id"] is not None:
                # Not a device addition session, redirect to home
                return RedirectResponse(url="/", status_code=303)

            # Create a device addition session token for the user
            client_info = get_client_info(request)
            session_token = await sql.create_session(
                session_data["user_id"], None, None, client_info
            )

            # Create response and set session cookie
            response = RedirectResponse(url="/auth/", status_code=303)
            set_session_cookie(response, session_token)

            return response

        except Exception:
            # On any error, redirect to home
            return RedirectResponse(url="/", status_code=303)


async def use_reset_token(token: str) -> dict:
    """Delete a device addition token after successful use."""
    try:
        # Get session token first to validate it exists and is not expired
        session_data = await sql.get_session(token)
        if not session_data:
            return {"error": "Invalid or expired device addition token"}

        # Check if this is a device addition session (credential_id is None)
        if session_data["credential_id"] is not None:
            return {"error": "Invalid device addition token"}

        # Delete the token (it's now used)
        await sql.delete_session(token)

        return {
            "status": "success",
            "message": "Device addition token used successfully",
        }

    except Exception as e:
        return {"error": f"Failed to use device addition token: {str(e)}"}
