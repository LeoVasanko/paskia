"""
API endpoints for user management and session handling.

This module contains all the HTTP API endpoints for:
- User information retrieval
- User credentials management
- Session token validation and refresh
- Login/logout functionality
"""

from fastapi import FastAPI, Request, Response

from .. import aaguid
from ..db import sql
from ..util.session import refresh_session_token, validate_session_token
from .session import (
    clear_session_cookie,
    get_current_user,
    get_session_token_from_bearer,
    get_session_token_from_cookie,
    set_session_cookie,
)


def register_api_routes(app: FastAPI):
    """Register all API routes on the FastAPI app."""

    @app.post("/auth/user-info")
    async def api_user_info(request: Request, response: Response):
        """Get user information and credentials from session cookie."""
        try:
            user = await get_current_user(request)
            if not user:
                return {"error": "Not authenticated"}

            # Get current session credential ID
            current_credential_id = None
            session_token = get_session_token_from_cookie(request)
            if session_token:
                token_data = await validate_session_token(session_token)
                if token_data:
                    current_credential_id = token_data.get("credential_id")

            # Get all credentials for the user
            credential_ids = await sql.get_user_credentials(user.user_id)

            credentials = []
            user_aaguids = set()

            for cred_id in credential_ids:
                stored_cred = await sql.get_credential_by_id(cred_id)

                # Convert AAGUID to string format
                aaguid_str = str(stored_cred.aaguid)
                user_aaguids.add(aaguid_str)

                # Check if this is the current session credential
                is_current_session = current_credential_id == stored_cred.credential_id

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

            # Get AAGUID information for only the AAGUIDs that the user has
            aaguid_info = aaguid.filter(user_aaguids)

            # Sort credentials by creation date (earliest first, most recently created last)
            credentials.sort(key=lambda cred: cred["created_at"])

            return {
                "status": "success",
                "user": {
                    "user_id": str(user.user_id),
                    "user_name": user.user_name,
                    "created_at": user.created_at.isoformat()
                    if user.created_at
                    else None,
                    "last_seen": user.last_seen.isoformat() if user.last_seen else None,
                    "visits": user.visits,
                },
                "credentials": credentials,
                "aaguid_info": aaguid_info,
            }
        except Exception as e:
            return {"error": f"Failed to get user info: {str(e)}"}

    @app.post("/auth/logout")
    async def api_logout(request: Request, response: Response):
        """Log out the current user by clearing the session cookie and deleting from database."""
        # Get the session token before clearing the cookie
        session_token = get_session_token_from_cookie(request)

        # Clear the cookie
        clear_session_cookie(response)

        # Delete the session from the database if it exists
        if session_token:
            from ..util.session import logout_session

            try:
                await logout_session(session_token)
            except Exception:
                # Continue even if session deletion fails
                pass

        return {"status": "success", "message": "Logged out successfully"}

    @app.post("/auth/set-session")
    async def api_set_session(request: Request, response: Response):
        """Set session cookie using JWT token from request body or Authorization header."""
        try:
            session_token = await get_session_token_from_bearer(request)

            if not session_token:
                return {"error": "No session token provided"}

            # Validate the session token
            token_data = await validate_session_token(session_token)
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

    @app.post("/auth/delete-credential")
    async def api_delete_credential(request: Request):
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

            # First, verify the credential belongs to the current user
            try:
                stored_cred = await sql.get_credential_by_id(credential_id_bytes)
                if stored_cred.user_id != user.user_id:
                    return {"error": "Credential not found or access denied"}
            except ValueError:
                return {"error": "Credential not found"}

            # Check if this is the current session credential
            session_token = get_session_token_from_cookie(request)
            if session_token:
                token_data = await validate_session_token(session_token)
                if (
                    token_data
                    and token_data.get("credential_id") == credential_id_bytes
                ):
                    return {"error": "Cannot delete current session credential"}

            # Get user's remaining credentials count
            remaining_credentials = await sql.get_user_credentials(user.user_id)
            if len(remaining_credentials) <= 1:
                return {"error": "Cannot delete last remaining credential"}

            # Delete the credential
            await sql.delete_user_credential(credential_id_bytes)

            return {"status": "success", "message": "Credential deleted successfully"}

        except Exception as e:
            return {"error": f"Failed to delete credential: {str(e)}"}

    @app.get("/auth/sessions")
    async def api_get_sessions(request: Request):
        """Get all active sessions for the current user."""
        try:
            user = await get_current_user(request)
            if not user:
                return {"error": "Authentication required"}

            # Get all sessions for this user
            from sqlalchemy import select

            from ..db.sql import SessionModel, connect

            async with connect() as db:
                stmt = select(SessionModel).where(
                    SessionModel.user_id == user.user_id.bytes
                )
                result = await db.session.execute(stmt)
                session_models = result.scalars().all()

                sessions = []
                current_token = get_session_token_from_cookie(request)

                for session in session_models:
                    # Check if session is expired
                    from datetime import datetime, timedelta

                    expiry_time = session.created_at + timedelta(hours=24)
                    is_expired = datetime.now() > expiry_time

                    sessions.append(
                        {
                            "token": session.token[:8]
                            + "...",  # Only show first 8 chars for security
                            "created_at": session.created_at.isoformat(),
                            "client_ip": session.info.get("client_ip")
                            if session.info
                            else None,
                            "user_agent": session.info.get("user_agent")
                            if session.info
                            else None,
                            "connection_type": session.info.get(
                                "connection_type", "http"
                            )
                            if session.info
                            else "http",
                            "is_current": session.token == current_token,
                            "is_reset_token": session.credential_id is None,
                            "is_expired": is_expired,
                        }
                    )

            return {
                "status": "success",
                "sessions": sessions,
                "total_sessions": len(sessions),
            }

        except Exception as e:
            return {"error": f"Failed to get sessions: {str(e)}"}


async def validate_token(request: Request, response: Response) -> dict:
    """Validate a session token and return user info. Also refreshes the token if valid."""
    try:
        session_token = get_session_token_from_cookie(request)
        if not session_token:
            return {"error": "No session token found"}

        # Validate the session token
        token_data = await validate_session_token(session_token)
        if not token_data:
            clear_session_cookie(response)
            return {"error": "Invalid or expired session token"}

        # Refresh the token if valid
        new_token = await refresh_session_token(session_token)
        if new_token:
            set_session_cookie(response, new_token)

        return {
            "status": "success",
            "valid": True,
            "refreshed": bool(new_token),
            "user_id": str(token_data["user_id"]),
            "credential_id": token_data["credential_id"].hex()
            if token_data["credential_id"]
            else None,
            "created_at": token_data["created_at"].isoformat(),
        }

    except Exception as e:
        return {"error": f"Failed to validate token: {str(e)}"}
