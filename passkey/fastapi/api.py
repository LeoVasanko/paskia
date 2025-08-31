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
from ..authsession import delete_credential, expires, get_reset, get_session
from ..globals import db
from ..globals import passkey as global_passkey
from ..util import tokens
from ..util.tokens import session_key
from . import authz, session

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
    async def validate_token(
        response: Response, perm: list[str] | None = None, auth=Cookie(None)
    ):
        """Lightweight token validation endpoint.

        Query Params:
        - perm: repeated permission IDs the caller must possess (ALL required)
        """

        s = await authz.verify(auth, perm)
        return {"valid": True, "user_uuid": str(s.user_uuid)}

    @app.post("/auth/user-info")
    async def api_user_info(reset: str | None = None, auth=Cookie(None)):
        """Get user information.

        - For authenticated sessions: return full context (org/role/permissions/credentials)
        - For reset tokens: return only basic user information to drive reset flow
        """
        authenticated = False
        try:
            if reset:
                if not passphrase.is_well_formed(reset):
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

        # Minimal response for reset tokens
        if not authenticated:
            return {
                "authenticated": False,
                "session_type": s.info.get("type"),
                "user": {
                    "user_uuid": str(u.uuid),
                    "user_name": u.display_name,
                },
            }

        # Full context for authenticated sessions
        assert authenticated and auth is not None
        ctx = await db.instance.get_session_context(session_key(auth))
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
        # Only global admins can modify org definitions (simpler rule)
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        from ..db import Org as OrgDC  # local import to avoid cycles

        current = await db.instance.get_organization(str(org_uuid))
        display_name = payload.get("display_name") or current.display_name
        permissions = payload.get("permissions") or current.permissions or []
        org = OrgDC(uuid=org_uuid, display_name=display_name, permissions=permissions)
        await db.instance.update_organization(org)
        return {"status": "ok"}

    @app.delete("/auth/admin/orgs/{org_uuid}")
    async def admin_delete_org(org_uuid: UUID, auth=Cookie(None)):
        ctx, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            # Org admins cannot delete at all (avoid self-lockout)
            raise ValueError("Global admin required")
        # Prevent deleting the organization that the acting global admin currently belongs to
        # if that deletion would remove their effective access (e.g., last org granting auth/admin)
        try:
            acting_org_uuid = ctx.org.uuid if ctx.org else None
        except Exception:
            acting_org_uuid = None
        if acting_org_uuid and acting_org_uuid == org_uuid:
            # Never allow deletion of the caller's own organization to avoid immediate account deletion.
            raise ValueError("Cannot delete the organization you belong to")
        await db.instance.delete_organization(org_uuid)
        return {"status": "ok"}

    # Manage an org's grantable permissions (query param for permission_id)
    @app.post("/auth/admin/orgs/{org_uuid}/permission")
    async def admin_add_org_permission(
        org_uuid: UUID, permission_id: str, auth=Cookie(None)
    ):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        await db.instance.add_permission_to_organization(str(org_uuid), permission_id)
        return {"status": "ok"}

    @app.delete("/auth/admin/orgs/{org_uuid}/permission")
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

    @app.post("/auth/admin/orgs/{org_uuid}/users")
    async def admin_create_user(
        org_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
    ):
        """Create a new user within an organization.

        Body parameters:
        - display_name: str (required)
        - role: str (required) display name of existing role in that org
        """
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        display_name = payload.get("display_name")
        role_name = payload.get("role")
        if not display_name or not role_name:
            raise ValueError("display_name and role are required")
        # Validate role exists in org
        from ..db import User as UserDC  # local import to avoid cycles

        roles = await db.instance.get_roles_by_organization(str(org_uuid))
        role_obj = next((r for r in roles if r.display_name == role_name), None)
        if not role_obj:
            raise ValueError("Role not found in organization")
        # Create user
        user_uuid = uuid4()
        user = UserDC(
            uuid=user_uuid,
            display_name=display_name,
            role_uuid=role_obj.uuid,
            visits=0,
            created_at=None,
        )
        await db.instance.create_user(user)
        return {"uuid": str(user_uuid)}

    @app.delete("/auth/admin/roles/{role_uuid}")
    async def admin_delete_role(role_uuid: UUID, auth=Cookie(None)):
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        role = await db.instance.get_role(role_uuid)
        if not (is_global_admin or (is_org_admin and role.org_uuid == ctx.org.uuid)):
            raise ValueError("Insufficient permissions")
        await db.instance.delete_role(role_uuid)
        return {"status": "ok"}

    # -------------------- Admin API: Users (role management) --------------------

    @app.put("/auth/admin/orgs/{org_uuid}/users/{user_uuid}/role")
    async def admin_update_user_role(
        org_uuid: UUID, user_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
    ):
        """Change a user's role within their organization.

        Body: {"role": "New Role Display Name"}
        Only global admins or admins of the organization can perform this.
        """
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
            raise ValueError("Insufficient permissions")
        new_role = payload.get("role")
        if not new_role:
            raise ValueError("role is required")
        # Verify user belongs to this org
        try:
            user_org, _current_role = await db.instance.get_user_organization(user_uuid)
        except ValueError:
            raise ValueError("User not found")
        if user_org.uuid != org_uuid:
            raise ValueError("User does not belong to this organization")
        # Ensure role exists in org and update
        roles = await db.instance.get_roles_by_organization(str(org_uuid))
        if not any(r.display_name == new_role for r in roles):
            raise ValueError("Role not found in organization")
        await db.instance.update_user_role_in_organization(user_uuid, new_role)
        return {"status": "ok"}

    @app.post("/auth/admin/users/{user_uuid}/create-link")
    async def admin_create_user_registration_link(user_uuid: UUID, auth=Cookie(None)):
        """Create a device registration/reset link for a specific user (admin only).

        Returns JSON: {"url": str, "expires": iso8601}
        """
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        # Ensure user exists and fetch their org
        try:
            user_org, _role_name = await db.instance.get_user_organization(user_uuid)
        except ValueError:
            raise HTTPException(status_code=404, detail="User not found")
        if not (is_global_admin or (is_org_admin and user_org.uuid == ctx.org.uuid)):
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Generate human-readable reset token and store as session with reset key
        token = passphrase.generate()
        await db.instance.create_session(
            user_uuid=user_uuid,
            key=tokens.reset_key(token),
            expires=expires(),
            info={"type": "device addition", "created_by_admin": True},
        )
        origin = global_passkey.instance.origin
        url = f"{origin}/auth/{token}"
        return {"url": url, "expires": expires().isoformat()}

    @app.get("/auth/admin/users/{user_uuid}")
    async def admin_get_user_detail(user_uuid: UUID, auth=Cookie(None)):
        """Get detailed information about a user (admin only)."""
        ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
        try:
            user_org, role_name = await db.instance.get_user_organization(user_uuid)
        except ValueError:
            raise HTTPException(status_code=404, detail="User not found")
        if not (is_global_admin or (is_org_admin and user_org.uuid == ctx.org.uuid)):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        user = await db.instance.get_user_by_uuid(user_uuid)
        # Gather credentials
        cred_ids = await db.instance.get_credentials_by_user_uuid(user_uuid)
        creds: list[dict] = []
        aaguids: set[str] = set()
        for cid in cred_ids:
            try:
                c = await db.instance.get_credential_by_id(cid)
            except ValueError:
                continue
            aaguid_str = str(c.aaguid)
            aaguids.add(aaguid_str)
            creds.append(
                {
                    "credential_uuid": str(c.uuid),
                    "aaguid": aaguid_str,
                    "created_at": c.created_at.isoformat(),
                    "last_used": c.last_used.isoformat() if c.last_used else None,
                    "last_verified": c.last_verified.isoformat()
                    if c.last_verified
                    else None,
                    "sign_count": c.sign_count,
                }
            )
        from .. import aaguid as aaguid_mod

        aaguid_info = aaguid_mod.filter(aaguids)
        return {
            "display_name": user.display_name,
            "org": {"display_name": user_org.display_name},
            "role": role_name,
            "visits": user.visits,
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "last_seen": user.last_seen.isoformat() if user.last_seen else None,
            "credentials": creds,
            "aaguid_info": aaguid_info,
        }

    # Admin API: Permissions (global)

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

    @app.put("/auth/admin/permission")
    async def admin_update_permission(
        permission_id: str, display_name: str, auth=Cookie(None)
    ):
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        from ..db import Permission as PermDC

        if not display_name:
            raise ValueError("display_name is required")
        await db.instance.update_permission(
            PermDC(id=permission_id, display_name=display_name)
        )
        return {"status": "ok"}

    @app.post("/auth/admin/permission/rename")
    async def admin_rename_permission(payload: dict = Body(...), auth=Cookie(None)):
        """Rename a permission's id (and optionally display name) updating all references.

        Body: { "old_id": str, "new_id": str, "display_name": str|null }
        """
        _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
        if not is_global_admin:
            raise ValueError("Global admin required")
        old_id = payload.get("old_id")
        new_id = payload.get("new_id")
        display_name = payload.get("display_name")
        if not old_id or not new_id:
            raise ValueError("old_id and new_id required")
        if display_name is None:
            # Fetch old to retain display name
            perm = await db.instance.get_permission(old_id)
            display_name = perm.display_name
        # rename_permission added to interface; use getattr for forward compatibility
        rename_fn = getattr(db.instance, "rename_permission", None)
        if not rename_fn:
            raise ValueError("Permission renaming not supported by this backend")
        await rename_fn(old_id, new_id, display_name)
        return {"status": "ok"}

    @app.delete("/auth/admin/permission")
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
        """Delete a specific credential for the current user."""
        await delete_credential(uuid, auth)
        return {"message": "Credential deleted successfully"}
