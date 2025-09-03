"""Admin sub-application.

All admin API endpoints previously under /auth/admin/* are now implemented
in this standalone FastAPI app which is mounted by the main application at
the /auth/admin path prefix. The routes defined here therefore omit the
"/auth/admin" prefix and start at root (e.g. "/orgs" becomes
"/auth/admin/orgs" once mounted).
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import Body, Cookie, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from ..authsession import expires, get_session
from ..globals import db
from ..globals import passkey as global_passkey
from ..util import passphrase, querysafe, tokens
from ..util.tokens import session_key

STATIC_DIR = Path(__file__).parent.parent / "frontend-build"

app = FastAPI()


@app.exception_handler(ValueError)
async def value_error_handler(_request, exc: ValueError):  # pragma: no cover - simple
    return JSONResponse(status_code=400, content={"detail": str(exc)})


async def _get_ctx_and_admin_flags(auth_cookie: str):
    """Helper to get session context and admin flags from cookie."""
    if not auth_cookie:
        raise ValueError("Not authenticated")
    ctx = await db.instance.get_session_context(session_key(auth_cookie))
    if not ctx:
        raise ValueError("Not authenticated")
    role_perm_ids = set(ctx.role.permissions or [])
    org_uuid_str = str(ctx.org.uuid)
    is_global_admin = "auth:admin" in role_perm_ids
    is_org_admin = f"auth:org:{org_uuid_str}" in role_perm_ids
    return ctx, is_global_admin, is_org_admin


@app.get("/")
@app.get("")
async def serve_admin_root(auth=Cookie(None)):
    """Serve the admin SPA root if an authenticated session exists.

    Mirrors previous behavior from mainapp. If no valid session, serve the
    main index.html with 401 so frontend can trigger login flow.
    """
    if auth:
        with contextlib.suppress(ValueError):
            s = await get_session(auth)
            if s.info and s.info.get("type") == "authenticated":
                return FileResponse(STATIC_DIR / "admin" / "index.html")
    return FileResponse(
        STATIC_DIR / "index.html",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


# -------------------- Organizations --------------------


@app.get("/orgs")
async def admin_list_orgs(auth=Cookie(None)):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    if not (is_global_admin or is_org_admin):
        raise ValueError("Insufficient permissions")
    orgs = await db.instance.list_organizations()
    if not is_global_admin:  # limit org admin to their own org
        orgs = [o for o in orgs if o.uuid == ctx.org.uuid]

    def role_to_dict(r):
        return {
            "uuid": str(r.uuid),
            "org_uuid": str(r.org_uuid),
            "display_name": r.display_name,
            "permissions": r.permissions,
        }

    async def org_to_dict(o):
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


@app.post("/orgs")
async def admin_create_org(payload: dict = Body(...), auth=Cookie(None)):
    _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
    if not is_global_admin:
        raise ValueError("Global admin required")
    from ..db import Org as OrgDC  # local import to avoid cycles

    org_uuid = uuid4()
    display_name = payload.get("display_name") or "New Organization"
    permissions = payload.get("permissions") or []
    org = OrgDC(uuid=org_uuid, display_name=display_name, permissions=permissions)
    await db.instance.create_organization(org)
    return {"uuid": str(org_uuid)}


@app.put("/orgs/{org_uuid}")
async def admin_update_org(
    org_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
):
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


@app.delete("/orgs/{org_uuid}")
async def admin_delete_org(org_uuid: UUID, auth=Cookie(None)):
    ctx, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
    if not is_global_admin:
        raise ValueError("Global admin required")
    try:
        acting_org_uuid = ctx.org.uuid if ctx.org else None
    except Exception:  # pragma: no cover - defensive
        acting_org_uuid = None
    if acting_org_uuid and acting_org_uuid == org_uuid:
        raise ValueError("Cannot delete the organization you belong to")
    await db.instance.delete_organization(org_uuid)
    return {"status": "ok"}


@app.post("/orgs/{org_uuid}/permission")
async def admin_add_org_permission(
    org_uuid: UUID, permission_id: str, auth=Cookie(None)
):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
        raise ValueError("Insufficient permissions")
    querysafe.assert_safe(permission_id, field="permission_id")
    await db.instance.add_permission_to_organization(str(org_uuid), permission_id)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/permission")
async def admin_remove_org_permission(
    org_uuid: UUID, permission_id: str, auth=Cookie(None)
):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
        raise ValueError("Insufficient permissions")
    querysafe.assert_safe(permission_id, field="permission_id")
    await db.instance.remove_permission_from_organization(str(org_uuid), permission_id)
    return {"status": "ok"}


# -------------------- Roles --------------------


@app.post("/orgs/{org_uuid}/roles")
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
    org = await db.instance.get_organization(str(org_uuid))
    grantable = set(org.permissions or [])
    for pid in permissions:
        await db.instance.get_permission(pid)
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


@app.put("/roles/{role_uuid}")
async def admin_update_role(
    role_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    role = await db.instance.get_role(role_uuid)
    if not (is_global_admin or (is_org_admin and role.org_uuid == ctx.org.uuid)):
        raise ValueError("Insufficient permissions")
    from ..db import Role as RoleDC

    display_name = payload.get("display_name") or role.display_name
    permissions = payload.get("permissions") or role.permissions
    org = await db.instance.get_organization(str(role.org_uuid))
    grantable = set(org.permissions or [])
    for pid in permissions:
        await db.instance.get_permission(pid)
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


@app.delete("/roles/{role_uuid}")
async def admin_delete_role(role_uuid: UUID, auth=Cookie(None)):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    role = await db.instance.get_role(role_uuid)
    if not (is_global_admin or (is_org_admin and role.org_uuid == ctx.org.uuid)):
        raise ValueError("Insufficient permissions")
    await db.instance.delete_role(role_uuid)
    return {"status": "ok"}


# -------------------- Users --------------------


@app.post("/orgs/{org_uuid}/users")
async def admin_create_user(
    org_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
        raise ValueError("Insufficient permissions")
    display_name = payload.get("display_name")
    role_name = payload.get("role")
    if not display_name or not role_name:
        raise ValueError("display_name and role are required")
    from ..db import User as UserDC

    roles = await db.instance.get_roles_by_organization(str(org_uuid))
    role_obj = next((r for r in roles if r.display_name == role_name), None)
    if not role_obj:
        raise ValueError("Role not found in organization")
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


@app.put("/orgs/{org_uuid}/users/{user_uuid}/role")
async def admin_update_user_role(
    org_uuid: UUID, user_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    if not (is_global_admin or (is_org_admin and ctx.org.uuid == org_uuid)):
        raise ValueError("Insufficient permissions")
    new_role = payload.get("role")
    if not new_role:
        raise ValueError("role is required")
    try:
        user_org, _current_role = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise ValueError("User not found")
    if user_org.uuid != org_uuid:
        raise ValueError("User does not belong to this organization")
    roles = await db.instance.get_roles_by_organization(str(org_uuid))
    if not any(r.display_name == new_role for r in roles):
        raise ValueError("Role not found in organization")
    await db.instance.update_user_role_in_organization(user_uuid, new_role)
    return {"status": "ok"}


@app.post("/users/{user_uuid}/create-link")
async def admin_create_user_registration_link(user_uuid: UUID, auth=Cookie(None)):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    try:
        user_org, _role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if not (is_global_admin or (is_org_admin and user_org.uuid == ctx.org.uuid)):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
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


@app.get("/users/{user_uuid}")
async def admin_get_user_detail(user_uuid: UUID, auth=Cookie(None)):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    try:
        user_org, role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if not (is_global_admin or (is_org_admin and user_org.uuid == ctx.org.uuid)):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    user = await db.instance.get_user_by_uuid(user_uuid)
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


@app.put("/users/{user_uuid}/display-name")
async def admin_update_user_display_name(
    user_uuid: UUID, payload: dict = Body(...), auth=Cookie(None)
):
    ctx, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    try:
        user_org, _role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if not (is_global_admin or (is_org_admin and user_org.uuid == ctx.org.uuid)):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    new_name = (payload.get("display_name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name required")
    if len(new_name) > 64:
        raise HTTPException(status_code=400, detail="display_name too long")
    await db.instance.update_user_display_name(user_uuid, new_name)
    return {"status": "ok"}


# -------------------- Permissions (global) --------------------


@app.get("/permissions")
async def admin_list_permissions(auth=Cookie(None)):
    _, is_global_admin, is_org_admin = await _get_ctx_and_admin_flags(auth)
    if not (is_global_admin or is_org_admin):
        raise ValueError("Insufficient permissions")
    perms = await db.instance.list_permissions()
    return [{"id": p.id, "display_name": p.display_name} for p in perms]


@app.post("/permissions")
async def admin_create_permission(payload: dict = Body(...), auth=Cookie(None)):
    _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
    if not is_global_admin:
        raise ValueError("Global admin required")
    from ..db import Permission as PermDC

    perm_id = payload.get("id")
    display_name = payload.get("display_name")
    if not perm_id or not display_name:
        raise ValueError("id and display_name are required")
    querysafe.assert_safe(perm_id, field="id")
    await db.instance.create_permission(PermDC(id=perm_id, display_name=display_name))
    return {"status": "ok"}


@app.put("/permission")
async def admin_update_permission(
    permission_id: str, display_name: str, auth=Cookie(None)
):
    _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
    if not is_global_admin:
        raise ValueError("Global admin required")
    from ..db import Permission as PermDC

    if not display_name:
        raise ValueError("display_name is required")
    querysafe.assert_safe(permission_id, field="permission_id")
    await db.instance.update_permission(
        PermDC(id=permission_id, display_name=display_name)
    )
    return {"status": "ok"}


@app.post("/permission/rename")
async def admin_rename_permission(payload: dict = Body(...), auth=Cookie(None)):
    _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
    if not is_global_admin:
        raise ValueError("Global admin required")
    old_id = payload.get("old_id")
    new_id = payload.get("new_id")
    display_name = payload.get("display_name")
    if not old_id or not new_id:
        raise ValueError("old_id and new_id required")
    querysafe.assert_safe(old_id, field="old_id")
    querysafe.assert_safe(new_id, field="new_id")
    if display_name is None:
        perm = await db.instance.get_permission(old_id)
        display_name = perm.display_name
    rename_fn = getattr(db.instance, "rename_permission", None)
    if not rename_fn:
        raise ValueError("Permission renaming not supported by this backend")
    await rename_fn(old_id, new_id, display_name)
    return {"status": "ok"}


@app.delete("/permission")
async def admin_delete_permission(permission_id: str, auth=Cookie(None)):
    _, is_global_admin, _ = await _get_ctx_and_admin_flags(auth)
    if not is_global_admin:
        raise ValueError("Global admin required")
    querysafe.assert_safe(permission_id, field="permission_id")
    await db.instance.delete_permission(permission_id)
    return {"status": "ok"}
