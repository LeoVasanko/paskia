"""Core (non-admin) HTTP API routes.

Contains endpoints for:
* Session validation
* Basic runtime settings
* Authenticated user info & credential listing
* User self-service updates (display name)
* Logout / set-session / credential deletion

Admin endpoints have been moved to `adminapp.py` and mounted at
`/auth/admin` by the main application.
"""

from uuid import UUID

from fastapi import Body, Cookie, Depends, FastAPI, HTTPException, Query, Response
from fastapi.security import HTTPBearer

from .. import aaguid
from ..authsession import delete_credential, get_reset, get_session
from ..globals import db
from ..globals import passkey as global_passkey
from ..util import tokens
from ..util.tokens import session_key
from . import authz, session

bearer_auth = HTTPBearer(auto_error=True)


def register_api_routes(app: FastAPI):
    """Register non-admin API routes on the FastAPI app."""

    @app.post("/auth/validate")
    async def validate_token(perm=Query(None), auth=Cookie(None)):
        s = await authz.verify(auth, perm)
        return {"valid": True, "user_uuid": str(s.user_uuid)}

    @app.get("/auth/settings")
    async def get_settings():
        pk = global_passkey.instance
        return {"rp_id": pk.rp_id, "rp_name": pk.rp_name}

    @app.post("/auth/user-info")
    async def api_user_info(reset: str | None = None, auth=Cookie(None)):
        authenticated = False
        try:
            if reset:
                if not tokens.passphrase.is_well_formed(reset):  # type: ignore[attr-defined]
                    raise ValueError("Invalid reset token")
                s = await get_reset(reset)
            else:
                if auth is None:
                    raise ValueError("Authentication Required")
                s = await get_session(auth)
                authenticated = True
        except ValueError as e:
            raise HTTPException(401, str(e))

        u = await db.instance.get_user_by_uuid(s.user_uuid)

        if not authenticated:  # minimal response for reset tokens
            return {
                "authenticated": False,
                "session_type": s.info.get("type"),
                "user": {"user_uuid": str(u.uuid), "user_name": u.display_name},
            }

        assert authenticated and auth is not None
        ctx = await db.instance.get_session_context(session_key(auth))
        credential_ids = await db.instance.get_credentials_by_user_uuid(s.user_uuid)
        credentials: list[dict] = []
        user_aaguids: set[str] = set()
        for cred_id in credential_ids:
            try:
                c = await db.instance.get_credential_by_id(cred_id)
            except ValueError:
                continue
            aaguid_str = str(c.aaguid)
            user_aaguids.add(aaguid_str)
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
                    "is_current_session": s.credential_uuid == c.uuid,
                }
            )
        credentials.sort(key=lambda cred: cred["created_at"])
        aaguid_info = aaguid.filter(user_aaguids)

        role_info = None
        org_info = None
        effective_permissions: list[str] = []
        is_global_admin = False
        is_org_admin = False
        if ctx:
            role_info = {
                "uuid": str(ctx.role.uuid),
                "display_name": ctx.role.display_name,
                "permissions": ctx.role.permissions,
            }
            org_info = {
                "uuid": str(ctx.org.uuid),
                "display_name": ctx.org.display_name,
                "permissions": ctx.org.permissions,
            }
            effective_permissions = [p.id for p in (ctx.permissions or [])]
            is_global_admin = "auth:admin" in (role_info["permissions"] or [])
            if org_info:
                is_org_admin = f"auth:org:{org_info['uuid']}" in (
                    role_info["permissions"] or []
                )

        return {
            "authenticated": True,
            "session_type": s.info.get("type"),
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

    @app.put("/auth/user/display-name")
    async def user_update_display_name(payload: dict = Body(...), auth=Cookie(None)):
        if not auth:
            raise HTTPException(status_code=401, detail="Authentication Required")
        s = await get_session(auth)
        new_name = (payload.get("display_name") or "").strip()
        if not new_name:
            raise HTTPException(status_code=400, detail="display_name required")
        if len(new_name) > 64:
            raise HTTPException(status_code=400, detail="display_name too long")
        await db.instance.update_user_display_name(s.user_uuid, new_name)
        return {"status": "ok"}

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
        """Set session cookie from Authorization Bearer session token (never via query)."""
        user = await get_session(auth.credentials)
        session.set_session_cookie(response, auth.credentials)

        return {
            "message": "Session cookie set successfully",
            "user_uuid": str(user.user_uuid),
        }

    @app.delete("/auth/credential/{uuid}")
    async def api_delete_credential(
        response: Response, uuid: UUID, auth: str = Cookie(None)
    ):
        await delete_credential(uuid, auth)
        return {"message": "Credential deleted successfully"}
