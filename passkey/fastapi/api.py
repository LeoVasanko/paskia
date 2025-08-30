"""
API endpoints for user management and session handling.

This module contains all the HTTP API endpoints for:
- User information retrieval
- User credentials management
- Session token validation and refresh
- Login/logout functionality
"""

from uuid import UUID, uuid4

from fastapi import Body, Cookie, Depends, FastAPI, HTTPException, Response
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

    async def _get_ctx_and_admin_flags(auth_cookie: str):
        """Helper to get session context and admin flags from cookie."""
        if not auth_cookie:
            raise ValueError("Not authenticated")
        ctx = await db.instance.get_session_context(session_key(auth_cookie))
        if not ctx:
            raise ValueError("Not authenticated")
        role_perm_ids = set(ctx.role.permissions or [])
        org_uuid_str = str(ctx.org.uuid)
        is_global_admin = "auth/admin" in role_perm_ids
        is_org_admin = f"auth/org:{org_uuid_str}" in role_perm_ids
        return ctx, is_global_admin, is_org_admin

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
        """Get user information.

        - For authenticated sessions: return full context (org/role/permissions/credentials)
        - For reset tokens: return only basic user information to drive reset flow
        """
        try:
            reset = auth and passphrase.is_well_formed(auth)
            s = await (get_reset if reset else get_session)(auth)
        except ValueError:
            raise HTTPException(
                status_code=401,
                detail="Authentication Required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Minimal response for reset tokens
        if reset:
            u = await db.instance.get_user_by_uuid(s.user_uuid)
            return {
                "authenticated": False,
                "session_type": s.info.get("type"),
                "user": {
                    "user_uuid": str(u.uuid),
                    "user_name": u.display_name,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                    "last_seen": u.last_seen.isoformat() if u.last_seen else None,
                    "visits": u.visits,
                },
            }

        # Full context for authenticated sessions
        ctx = await db.instance.get_session_context(session_key(auth))
        u = await db.instance.get_user_by_uuid(s.user_uuid)
        credential_ids = await db.instance.get_credentials_by_user_uuid(s.user_uuid)

        credentials: list[dict] = []
        user_aaguids: set[str] = set()
        for cred_id in credential_ids:
            try:
                c = await db.instance.get_credential_by_id(cred_id)
            except ValueError:
                continue  # Skip dangling IDs
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

        credentials.sort(key=lambda cred: cred["created_at"])  # chronological
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
            is_global_admin = "auth/admin" in role_info["permissions"]
            is_org_admin = (
                f"auth/org:{org_info['uuid']}" in role_info["permissions"]
                if org_info
                else False
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

    # -------------------- Admin API: Organizations --------------------

    @app.get("/auth/admin/orgs")
    async def admin_list_orgs(auth=Cookie(None)):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or is_org_admin):
            raise ValueError("Insufficient permissions")
        orgs = await db.instance.list_organizations()
        # If only org admin, filter to their org
        if not is_global_admin:
            orgs = [o for o in orgs if o.uuid == ctx.org.uuid]

        def role_to_dict(r):
            return {
                "uuid": str(r.uuid),
                "org_uuid": str(r.org_uuid),
                "display_name": r.display_name,
                "permissions": r.permissions,
            }

        async def org_to_dict(o):
            # Fetch users for each org
            users = await db.instance.get_organization_users(str(o.uuid))
            return {
                "uuid": str(o.uuid),
                "display_name": o.display_name,
                "permissions": o.permissions,
                "roles": [role_to_dict(r) for r in o.roles],
                "users": [
                    {
                        "uuid": str(u.uuid),
                        "display_name": u.display_name,
                        "role": role_name,
                        "visits": u.visits,
                        "last_seen": u.last_seen.isoformat() if u.last_seen else None,
                    }
                    for (u, role_name) in users
                ],
            }

        return [await org_to_dict(o) for o in orgs]

    @app.post("/auth/admin/orgs")
    async def admin_create_org(payload: dict = Body(...), auth=Cookie(None)):
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        from ..db import Org as OrgDC  # local import to avoid cycles in typing

        org_uuid = uuid4()
        display_name = payload.get("display_name") or "New Organization"
        permissions = payload.get("permissions") or []
        org = OrgDC(uuid=org_uuid, display_name=display_name, permissions=permissions)
        await db.instance.create_organization(org)
        return {"uuid": str(org_uuid)}

    @app.put("/auth/admin/orgs/{org_uuid}")
    async def admin_update_org(
        org_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
    ):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        from ..db import Org as OrgDC

        current = await db.instance.get_organization(str(org_uuid))
        display_name = payload.get("display_name") or current.display_name
        permissions = (
            payload.get("permissions")
            if "permissions" in payload
            else current.permissions
        ) or []
        org = OrgDC(uuid=org_uuid, display_name=display_name, permissions=permissions)
        await db.instance.update_organization(org)
        return {"status": "ok"}

    @app.delete("/auth/admin/orgs/{org_uuid}")
    async def admin_delete_org(org_uuid: UUID, auth=Cookie(None)):
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        await db.instance.delete_organization(org_uuid)
        return {"status": "ok"}

    # Manage an org's grantable permissions
    @app.post("/auth/admin/orgs/{org_uuid}/permissions/{permission_id}")
    async def admin_add_org_permission(
        org_uuid: UUID, permission_id: str, auth=Cookie(None)
    ):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        await db.instance.add_permission_to_organization(str(org_uuid), permission_id)
        return {"status": "ok"}

    @app.delete("/auth/admin/orgs/{org_uuid}/permissions/{permission_id}")
    async def admin_remove_org_permission(
        org_uuid: UUID, permission_id: str, auth=Cookie(None)
    ):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        await db.instance.remove_permission_from_organization(
            str(org_uuid), permission_id
        )
        return {"status": "ok"}

    # -------------------- Admin API: Roles --------------------

    @app.post("/auth/admin/orgs/{org_uuid}/roles")
    async def admin_create_role(
        org_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
    ):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        from ..db import Role as RoleDC

        role_uuid = uuid4()
        display_name = payload.get("display_name") or "New Role"
        permissions = payload.get("permissions") or []
        # Validate that permissions exist and are allowed by org
        org = await db.instance.get_organization(str(org_uuid))
        grantable = set(org.permissions or [])
        for pid in permissions:
            await db.instance.get_permission(pid)  # raises if not found
            if pid not in grantable:
                raise ValueError(f"Permission not grantable by org: {pid}")
        role = RoleDC(
            uuid=role_uuid,
            org_uuid=org_uuid,
            display_name=display_name,
            permissions=permissions,
        )
        await db.instance.create_role(role)
        return {"uuid": str(role_uuid)}

    @app.put("/auth/admin/roles/{role_uuid}")
    async def admin_update_role(
        role_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
    ):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        role = await db.instance.get_role(role_uuid)
        # Only org admins for that org or global admin can update
        if not (is_global_admin or (is_org_admin and role.org_uuid == ctx.org.uuid)):
            raise ValueError("Insufficient permissions")
        from ..db import Role as RoleDC

        display_name = payload.get("display_name") or role.display_name
        permissions = payload.get("permissions") or role.permissions
        # Validate against org grantable permissions
        org = await db.instance.get_organization(str(role.org_uuid))
        grantable = set(org.permissions or [])
        for pid in permissions:
            await db.instance.get_permission(pid)  # raises if not found
            if pid not in grantable:
                raise ValueError(f"Permission not grantable by org: {pid}")
        updated = RoleDC(
            uuid=role_uuid,
            org_uuid=role.org_uuid,
            display_name=display_name,
            permissions=permissions,
        )
        await db.instance.update_role(updated)
        return {"status": "ok"}

    @app.delete("/auth/admin/roles/{role_uuid}")
    async def admin_delete_role(role_uuid: UUID, auth=Cookie(None)):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        role = await db.instance.get_role(role_uuid)
        if not (is_global_admin or (is_org_admin and role.org_uuid == ctx.org.uuid)):
            raise ValueError("Insufficient permissions")
        await db.instance.delete_role(role_uuid)
        return {"status": "ok"}

    # -------------------- Admin API: Permissions (global) --------------------

    @app.get("/auth/admin/permissions")
    async def admin_list_permissions(auth=Cookie(None)):
        _, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or is_org_admin):
            raise ValueError("Insufficient permissions")
        perms = await db.instance.list_permissions()
        return [{"id": p.id, "display_name": p.display_name} for p in perms]

    @app.post("/auth/admin/permissions")
    async def admin_create_permission(payload: dict = Body(...), auth=Cookie(None)):
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        from ..db import Permission as PermDC

        perm_id = payload.get("id")
        display_name = payload.get("display_name")
        if not perm_id or not display_name:
            raise ValueError("id and display_name are required")
        await db.instance.create_permission(
            PermDC(id=perm_id, display_name=display_name)
        )
        return {"status": "ok"}

    @app.put("/auth/admin/permissions/{permission_id}")
    async def admin_update_permission(
        permission_id: str, payload: dict = Body(...), auth=Cookie(None)
    ):
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        from ..db import Permission as PermDC

        display_name = payload.get("display_name")
        if not display_name:
            raise ValueError("display_name is required")
        await db.instance.update_permission(
            PermDC(id=permission_id, display_name=display_name)
        )
        return {"status": "ok"}

    @app.delete("/auth/admin/permissions/{permission_id}")
    async def admin_delete_permission(permission_id: str, auth=Cookie(None)):
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        await db.instance.delete_permission(permission_id)
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
