"""
API endpoints for user management and session handling.

This module contains all the HTTP API endpoints for:
- User information retrieval
- User credentials management
- Session token validation and refresh
- Login/logout functionality
"""

from uuid import UUID

from fastapi import Cookie, Depends, FastAPI, Response
from fastapi.security import HTTPBearer

from passkey.util import passphrase

from .. import aaguid
from ..authsession import delete_credential, get_reset, get_session
from ..globals import db
from ..util.tokens import session_key
from . import session

bearer_auth = HTTPBearer(auto_error=True)


def register_api_routes(app: FastAPI):
    """Register all API routes on the FastAPI app."""

    @app.post("/auth/validate")
    async def validate_token(response: Response, auth=Cookie(None)):
        """Lightweight token validation endpoint."""
        s = await get_session(auth)
        return {
            "valid": True,
            "user_uuid": str(s.user_uuid),
        }

    @app.post("/auth/user-info")
    async def api_user_info(response: Response, auth=Cookie(None)):
        """Get full user information for the authenticated user."""
        reset = passphrase.is_well_formed(auth)
        s = await (get_reset if reset else get_session)(auth)
        # Session context (org, role, permissions)
        ctx = await db.instance.get_session_context(session_key(auth))
        # Fallback if context not available (e.g., reset session)
        u = await db.instance.get_user_by_uuid(s.user_uuid)
        # Get all credentials for the user
        credential_ids = await db.instance.get_credentials_by_user_uuid(s.user_uuid)

        credentials = []
        user_aaguids = set()

        for cred_id in credential_ids:
            c = await db.instance.get_credential_by_id(cred_id)

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

        # Permissions and roles
        role_info = None
        org_info = None
        effective_permissions = []
        is_global_admin = False
        is_org_admin = False
        if ctx:
            role_info = {
                "uuid": str(ctx.role.uuid),
                "display_name": ctx.role.display_name,
                "permissions": ctx.role.permissions,  # IDs
            }
            org_info = {
                "uuid": str(ctx.org.uuid),
                "display_name": ctx.org.display_name,
                "permissions": ctx.org.permissions,  # IDs the org can grant
            }
            # Effective permissions are role permissions; API also returns full objects for convenience
            effective_permissions = [p.id for p in (ctx.permissions or [])]
            is_global_admin = "auth/admin" in role_info["permissions"]
            # org admin permission is auth/org:<org_uuid>
            is_org_admin = (
                f"auth/org:{org_info['uuid']}" in role_info["permissions"]
                if org_info
                else False
            )

        return {
            "authenticated": not reset,
            "session_type": s.info["type"],
            "user": {
                "user_uuid": str(u.uuid),
                "user_name": u.display_name,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "last_seen": u.last_seen.isoformat() if u.last_seen else None,
                "visits": u.visits,
            },
            "org": org_info,
            "role": role_info,
            "permissions": effective_permissions,
            "is_global_admin": is_global_admin,
            "is_org_admin": is_org_admin,
            "credentials": credentials,
            "aaguid_info": aaguid_info,
        }

    @app.post("/auth/logout")
    async def api_logout(response: Response, auth=Cookie(None)):
        """Log out the current user by clearing the session cookie and deleting from database."""
        if not auth:
            return {"message": "Already logged out"}
        # Remove from database if possible
        try:
            await db.instance.delete_session(session_key(auth))
        except Exception:
            ...
        response.delete_cookie("auth")
        return {"message": "Logged out successfully"}

    @app.post("/auth/set-session")
    async def api_set_session(response: Response, auth=Depends(bearer_auth)):
        """Set session cookie from Authorization header. Fetched after login by WebSocket."""
        user = await get_session(auth.credentials)
        if not user:
            raise ValueError("Invalid Authorization header.")
        session.set_session_cookie(response, auth.credentials)

        return {
            "message": "Session cookie set successfully",
            "user_uuid": str(user.user_uuid),
        }

    @app.delete("/auth/credential/{uuid}")
    async def api_delete_credential(
        response: Response, uuid: UUID, auth: str = Cookie(None)
    ):
        """Delete a specific credential for the current user."""
        await delete_credential(uuid, auth)
        return {"message": "Credential deleted successfully"}
