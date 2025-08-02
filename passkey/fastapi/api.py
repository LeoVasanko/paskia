"""
API endpoints for user management and session handling.

This module contains all the HTTP API endpoints for:
- User information retrieval
- User credentials management
- Session token validation and refresh
- Login/logout functionality
"""

from uuid import UUID

from fastapi import Cookie, Depends, FastAPI, Request, Response
from fastapi.security import HTTPBearer

from .. import aaguid
from ..db import sql
from ..util.tokens import session_key
from . import session

bearer_auth = HTTPBearer(auto_error=True)


def register_api_routes(app: FastAPI):
    """Register all API routes on the FastAPI app."""

    @app.post("/auth/validate")
    async def validate_token(request: Request, response: Response, auth=Cookie(None)):
        """Lightweight token validation endpoint."""
        try:
            s = await session.get_session(auth)
            return {
                "status": "success",
                "valid": True,
                "user_uuid": str(s.user_uuid),
            }
        except ValueError:
            return {"status": "error", "valid": False}

    @app.post("/auth/user-info")
    async def api_user_info(request: Request, response: Response, auth=Cookie(None)):
        """Get full user information for the authenticated user."""
        try:
            s = await session.get_session(auth, reset_allowed=True)
            u = await sql.get_user_by_uuid(s.user_uuid)
            # Get all credentials for the user
            credential_ids = await sql.get_user_credentials(s.user_uuid)

            credentials = []
            user_aaguids = set()

            for cred_id in credential_ids:
                c = await sql.get_credential_by_id(cred_id)

                # Convert AAGUID to string format
                aaguid_str = str(c.aaguid)
                user_aaguids.add(aaguid_str)

                # Check if this is the current session credential
                is_current_session = s.credential_uuid == c.uuid

                credentials.append(
                    {
                        "credential_uuid": str(c.uuid),
                        "aaguid": aaguid_str,
                        "created_at": c.created_at.isoformat(),
                        "last_used": c.last_used.isoformat() if c.last_used else None,
                        "last_verified": c.last_verified.isoformat()
                        if c.last_verified
                        else None,
                        "sign_count": c.sign_count,
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
                    "user_uuid": str(u.user_uuid),
                    "user_name": u.user_name,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                    "last_seen": u.last_seen.isoformat() if u.last_seen else None,
                    "visits": u.visits,
                },
                "credentials": credentials,
                "aaguid_info": aaguid_info,
            }
        except Exception as e:
            return {"error": f"Failed to get user info: {str(e)}"}

    @app.post("/auth/logout")
    async def api_logout(response: Response, auth=Cookie(None)):
        """Log out the current user by clearing the session cookie and deleting from database."""
        if not auth:
            return {"status": "success", "message": "Already logged out"}
        await sql.delete_session(session_key(auth))
        response.delete_cookie("auth")
        return {"status": "success", "message": "Logged out successfully"}

    @app.post("/auth/set-session")
    async def api_set_session(
        request: Request, response: Response, auth=Depends(bearer_auth)
    ):
        """Set session cookie from Authorization header. Fetched after login by WebSocket."""
        try:
            user = await session.get_session(auth.credentials)
            if not user:
                raise ValueError("Invalid Authorization header.")
            session.set_session_cookie(response, auth.credentials)

            return {
                "status": "success",
                "message": "Session cookie set successfully",
                "user_uuid": str(user.user_uuid),
            }

        except ValueError as e:
            return {"error": str(e)}
        except Exception as e:
            return {"error": f"Failed to set session: {str(e)}"}

    @app.delete("/auth/credential/{uuid}")
    async def api_delete_credential(uuid: UUID, auth: str = Cookie(None)):
        """Delete a specific credential for the current user."""
        try:
            await session.delete_credential(uuid, auth)
            return {"status": "success", "message": "Credential deleted successfully"}

        except ValueError as e:
            return {"error": str(e)}
        except Exception:
            return {"error": "Failed to delete credential"}
