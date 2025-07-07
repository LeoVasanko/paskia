"""
API endpoints for user management and session handling.

This module contains all the HTTP API endpoints for:
- User information retrieval
- User credentials management
- Session token validation and refresh
- Login/logout functionality
"""

from fastapi import Request, Response

from .aaguid_manager import get_aaguid_manager
from .db import connect
from .jwt_manager import refresh_session_token, validate_session_token
from .session_manager import (
    clear_session_cookie,
    get_current_user,
    get_session_token_from_auth_header_or_body,
    get_session_token_from_request,
    set_session_cookie,
)


async def get_user_info(request: Request) -> dict:
    """Get user information from session cookie."""
    try:
        user = await get_current_user(request)
        if not user:
            return {"error": "Not authenticated"}

        return {
            "status": "success",
            "user": {
                "user_id": str(user.user_id),
                "user_name": user.user_name,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_seen": user.last_seen.isoformat() if user.last_seen else None,
            },
        }
    except Exception as e:
        return {"error": f"Failed to get user info: {str(e)}"}


async def get_user_credentials(request: Request) -> dict:
    """Get all credentials for a user using session cookie."""
    try:
        user = await get_current_user(request)
        if not user:
            return {"error": "Not authenticated"}

        # Get current session credential ID
        current_credential_id = None
        session_token = get_session_token_from_request(request)
        if session_token:
            token_data = validate_session_token(session_token)
            if token_data:
                current_credential_id = token_data.get("credential_id")

        async with connect() as db:
            # Get all credentials for the user
            credential_ids = await db.get_credentials_by_user_id(user.user_id.bytes)

            credentials = []
            user_aaguids = set()

            for cred_id in credential_ids:
                try:
                    stored_cred = await db.get_credential_by_id(cred_id)

                    # Convert AAGUID to string format
                    aaguid_str = str(stored_cred.aaguid)
                    user_aaguids.add(aaguid_str)

                    # Check if this is the current session credential
                    is_current_session = (
                        current_credential_id == stored_cred.credential_id
                    )

                    credentials.append(
                        {
                            "credential_id": stored_cred.credential_id.hex(),
                            "aaguid": aaguid_str,
                            "created_at": stored_cred.created_at.isoformat(),
                            "last_used": stored_cred.last_used.isoformat()
                            if stored_cred.last_used
                            else None,
                            "last_verified": stored_cred.last_verified.isoformat()
                            if stored_cred.last_verified
                            else None,
                            "sign_count": stored_cred.sign_count,
                            "is_current_session": is_current_session,
                        }
                    )
                except ValueError:
                    # Skip invalid credentials
                    continue

            # Get AAGUID information for only the AAGUIDs that the user has
            aaguid_manager = get_aaguid_manager()
            aaguid_info = aaguid_manager.get_relevant_aaguids(user_aaguids)

            # Sort credentials by creation date (earliest first, most recently created last)
            credentials.sort(key=lambda cred: cred["created_at"])

            return {
                "status": "success",
                "credentials": credentials,
                "aaguid_info": aaguid_info,
            }
    except Exception as e:
        return {"error": f"Failed to get credentials: {str(e)}"}


async def refresh_token(request: Request, response: Response) -> dict:
    """Refresh the session token."""
    try:
        session_token = get_session_token_from_request(request)
        if not session_token:
            return {"error": "No session token found"}

        # Validate and refresh the token
        new_token = refresh_session_token(session_token)

        if new_token:
            set_session_cookie(response, new_token)
            return {"status": "success", "refreshed": True}
        else:
            clear_session_cookie(response)
            return {"error": "Invalid or expired session token"}

    except Exception as e:
        return {"error": f"Failed to refresh token: {str(e)}"}


async def validate_token(request: Request) -> dict:
    """Validate a session token and return user info."""
    try:
        session_token = get_session_token_from_request(request)
        if not session_token:
            return {"error": "No session token found"}

        # Validate the session token
        token_data = validate_session_token(session_token)
        if not token_data:
            return {"error": "Invalid or expired session token"}

        return {
            "status": "success",
            "valid": True,
            "user_id": str(token_data["user_id"]),
            "credential_id": token_data["credential_id"].hex(),
            "issued_at": token_data["issued_at"],
            "expires_at": token_data["expires_at"],
        }

    except Exception as e:
        return {"error": f"Failed to validate token: {str(e)}"}


async def logout(response: Response) -> dict:
    """Log out the current user by clearing the session cookie."""
    clear_session_cookie(response)
    return {"status": "success", "message": "Logged out successfully"}


async def set_session(request: Request, response: Response) -> dict:
    """Set session cookie using JWT token from request body or Authorization header."""
    try:
        session_token = await get_session_token_from_auth_header_or_body(request)

        if not session_token:
            return {"error": "No session token provided"}

        # Validate the session token
        token_data = validate_session_token(session_token)
        if not token_data:
            return {"error": "Invalid or expired session token"}

        # Set the HTTP-only cookie
        set_session_cookie(response, session_token)

        return {
            "status": "success",
            "message": "Session cookie set successfully",
            "user_id": str(token_data["user_id"]),
        }

    except Exception as e:
        return {"error": f"Failed to set session: {str(e)}"}


async def delete_credential(request: Request) -> dict:
    """Delete a specific credential for the current user."""
    try:
        user = await get_current_user(request)
        if not user:
            return {"error": "Not authenticated"}

        # Get the credential ID from the request body
        try:
            body = await request.json()
            credential_id = body.get("credential_id")
            if not credential_id:
                return {"error": "credential_id is required"}
        except Exception:
            return {"error": "Invalid request body"}

        # Convert credential_id from hex string to bytes
        try:
            credential_id_bytes = bytes.fromhex(credential_id)
        except ValueError:
            return {"error": "Invalid credential_id format"}

        async with connect() as db:
            # First, verify the credential belongs to the current user
            try:
                stored_cred = await db.get_credential_by_id(credential_id_bytes)
                if stored_cred.user_id != user.user_id:
                    return {"error": "Credential not found or access denied"}
            except ValueError:
                return {"error": "Credential not found"}

            # Check if this is the current session credential
            session_token = get_session_token_from_request(request)
            if session_token:
                token_data = validate_session_token(session_token)
                if (
                    token_data
                    and token_data.get("credential_id") == credential_id_bytes
                ):
                    return {"error": "Cannot delete current session credential"}

            # Get user's remaining credentials count
            remaining_credentials = await db.get_credentials_by_user_id(
                user.user_id.bytes
            )
            if len(remaining_credentials) <= 1:
                return {"error": "Cannot delete last remaining credential"}

            # Delete the credential
            await db.delete_credential(credential_id_bytes)

            return {"status": "success", "message": "Credential deleted successfully"}

    except Exception as e:
        return {"error": f"Failed to delete credential: {str(e)}"}
