import logging
from datetime import timezone
from uuid import UUID, uuid4

from fastapi import Body, Cookie, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from ..authsession import reset_expires
from ..globals import db
from ..util import (
    frontend,
    hostutil,
    passphrase,
    permutil,
    querysafe,
    tokens,
    useragent,
)
from ..util.tokens import encode_session_key, session_key
from . import authz

app = FastAPI()


@app.exception_handler(ValueError)
async def value_error_handler(_request, exc: ValueError):  # pragma: no cover - simple
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def general_exception_handler(_request, exc: Exception):
    logging.exception("Unhandled exception in admin app")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/")
async def adminapp(request: Request, auth=Cookie(None, alias="__Host-auth")):
    """Serve admin SPA only for authenticated users with admin/org permissions.

    On missing/invalid session or insufficient permissions, serve restricted SPA.
    """
    try:
        await authz.verify(
            auth,
            ["auth:admin", "auth:org:*"],
            match=permutil.has_any,
            host=request.headers.get("host"),
        )
        return FileResponse(frontend.file("admin/index.html"))
    except HTTPException as e:
        return FileResponse(
            frontend.file("restricted", "index.html"), status_code=e.status_code
        )


# -------------------- Organizations --------------------


@app.get("/orgs")
async def admin_list_orgs(request: Request, auth=Cookie(None, alias="__Host-auth")):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:*"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    orgs = await db.instance.list_organizations()
    if "auth:admin" not in ctx.role.permissions:
        orgs = [o for o in orgs if f"auth:org:{o.uuid}" in ctx.role.permissions]

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
async def admin_create_org(
    request: Request, payload: dict = Body(...), auth=Cookie(None, alias="__Host-auth")
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
    from ..db import Org as OrgDC  # local import to avoid cycles
    from ..db import Role as RoleDC  # local import to avoid cycles

    org_uuid = uuid4()
    display_name = payload.get("display_name") or "New Organization"
    permissions = payload.get("permissions") or []
    org = OrgDC(uuid=org_uuid, display_name=display_name, permissions=permissions)
    await db.instance.create_organization(org)

    # Automatically create Administration role with org admin permission
    role_uuid = uuid4()
    admin_role = RoleDC(
        uuid=role_uuid,
        org_uuid=org_uuid,
        display_name="Administration",
        permissions=[f"auth:org:{org_uuid}"],
    )
    await db.instance.create_role(admin_role)

    return {"uuid": str(org_uuid)}


@app.put("/orgs/{org_uuid}")
async def admin_update_org(
    org_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    from ..db import Org as OrgDC  # local import to avoid cycles

    current = await db.instance.get_organization(str(org_uuid))
    display_name = payload.get("display_name") or current.display_name
    permissions = payload.get("permissions") or current.permissions or []

    # Sanity check: prevent removing permissions that would break current user's admin access
    org_admin_perm = f"auth:org:{org_uuid}"

    # If current user is org admin (not global admin), ensure org admin perm remains
    if (
        "auth:admin" not in ctx.role.permissions
        and f"auth:org:{org_uuid}" in ctx.role.permissions
    ):
        if org_admin_perm not in permissions:
            raise ValueError(
                "Cannot remove organization admin permission from your own organization"
            )

    org = OrgDC(uuid=org_uuid, display_name=display_name, permissions=permissions)
    await db.instance.update_organization(org)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}")
async def admin_delete_org(
    org_uuid: UUID, request: Request, auth=Cookie(None, alias="__Host-auth")
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if ctx.org.uuid == org_uuid:
        raise ValueError("Cannot delete the organization you belong to")

    # Delete organization-specific permissions
    org_perm_pattern = f"org:{str(org_uuid).lower()}"
    all_permissions = await db.instance.list_permissions()
    for perm in all_permissions:
        perm_id_lower = perm.id.lower()
        # Check if permission contains "org:{uuid}" separated by colons or at boundaries
        if (
            f":{org_perm_pattern}:" in perm_id_lower
            or perm_id_lower.startswith(f"{org_perm_pattern}:")
            or perm_id_lower.endswith(f":{org_perm_pattern}")
            or perm_id_lower == org_perm_pattern
        ):
            await db.instance.delete_permission(perm.id)

    await db.instance.delete_organization(org_uuid)
    return {"status": "ok"}


@app.post("/orgs/{org_uuid}/permission")
async def admin_add_org_permission(
    org_uuid: UUID,
    permission_id: str,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
    await db.instance.add_permission_to_organization(str(org_uuid), permission_id)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/permission")
async def admin_remove_org_permission(
    org_uuid: UUID,
    permission_id: str,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
    await db.instance.remove_permission_from_organization(str(org_uuid), permission_id)
    return {"status": "ok"}


# -------------------- Roles --------------------


@app.post("/orgs/{org_uuid}/roles")
async def admin_create_role(
    org_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    from ..db import Role as RoleDC

    role_uuid = uuid4()
    display_name = payload.get("display_name") or "New Role"
    perms = payload.get("permissions") or []
    org = await db.instance.get_organization(str(org_uuid))
    grantable = set(org.permissions or [])
    for pid in perms:
        await db.instance.get_permission(pid)
        if pid not in grantable:
            raise ValueError(f"Permission not grantable by org: {pid}")
    role = RoleDC(
        uuid=role_uuid,
        org_uuid=org_uuid,
        display_name=display_name,
        permissions=perms,
    )
    await db.instance.create_role(role)
    return {"uuid": str(role_uuid)}


@app.put("/orgs/{org_uuid}/roles/{role_uuid}")
async def admin_update_role(
    org_uuid: UUID,
    role_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    # Verify caller is global admin or admin of provided org
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    role = await db.instance.get_role(role_uuid)
    if role.org_uuid != org_uuid:
        raise HTTPException(status_code=404, detail="Role not found in organization")
    from ..db import Role as RoleDC

    display_name = payload.get("display_name") or role.display_name
    permissions = payload.get("permissions")
    if permissions is None:
        permissions = role.permissions
    org = await db.instance.get_organization(str(org_uuid))
    grantable = set(org.permissions or [])
    existing_permissions = set(role.permissions)
    for pid in permissions:
        await db.instance.get_permission(pid)
        if pid not in existing_permissions and pid not in grantable:
            raise ValueError(f"Permission not grantable by org: {pid}")

    # Sanity check: prevent admin from removing their own access via role update
    if ctx.org.uuid == org_uuid and ctx.role.uuid == role_uuid:
        has_admin_access = (
            "auth:admin" in permissions or f"auth:org:{org_uuid}" in permissions
        )
        if not has_admin_access:
            raise ValueError("Cannot update your own role to remove admin permissions")

    updated = RoleDC(
        uuid=role_uuid,
        org_uuid=org_uuid,
        display_name=display_name,
        permissions=permissions,
    )
    await db.instance.update_role(updated)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/roles/{role_uuid}")
async def admin_delete_role(
    org_uuid: UUID,
    role_uuid: UUID,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    role = await db.instance.get_role(role_uuid)
    if role.org_uuid != org_uuid:
        raise HTTPException(status_code=404, detail="Role not found in organization")

    # Sanity check: prevent admin from deleting their own role
    if ctx.role.uuid == role_uuid:
        raise ValueError("Cannot delete your own role")

    await db.instance.delete_role(role_uuid)
    return {"status": "ok"}


# -------------------- Users --------------------


@app.post("/orgs/{org_uuid}/users")
async def admin_create_user(
    org_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
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
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
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

    # Sanity check: prevent admin from removing their own access
    if ctx.user.uuid == user_uuid:
        new_role_obj = next((r for r in roles if r.display_name == new_role), None)
        if new_role_obj:
            has_admin_access = (
                "auth:admin" in new_role_obj.permissions
                or f"auth:org:{org_uuid}" in new_role_obj.permissions
            )
            if not has_admin_access:
                raise ValueError(
                    "Cannot change your own role to one without admin permissions"
                )

    await db.instance.update_user_role_in_organization(user_uuid, new_role)
    return {"status": "ok"}


@app.post("/orgs/{org_uuid}/users/{user_uuid}/create-link")
async def admin_create_user_registration_link(
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    try:
        user_org, _role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if (
        "auth:admin" not in ctx.role.permissions
        and f"auth:org:{org_uuid}" not in ctx.role.permissions
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Check if user has existing credentials
    credentials = await db.instance.get_credentials_by_user_uuid(user_uuid)
    token_type = "user registration" if not credentials else "account recovery"

    token = passphrase.generate()
    expiry = reset_expires()
    await db.instance.create_reset_token(
        user_uuid=user_uuid,
        key=tokens.reset_key(token),
        expiry=expiry,
        token_type=token_type,
    )
    url = hostutil.reset_link_url(
        token, request.url.scheme, request.headers.get("host")
    )
    return {
        "url": url,
        "expires": (
            expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if expiry.tzinfo
            else expiry.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        ),
    }


@app.get("/orgs/{org_uuid}/users/{user_uuid}")
async def admin_get_user_detail(
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    try:
        user_org, role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if (
        "auth:admin" not in ctx.role.permissions
        and f"auth:org:{org_uuid}" not in ctx.role.permissions
    ):
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
                "created_at": (
                    c.created_at.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if c.created_at.tzinfo
                    else c.created_at.replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                ),
                "last_used": (
                    c.last_used.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if c.last_used and c.last_used.tzinfo
                    else (
                        c.last_used.replace(tzinfo=timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                        if c.last_used
                        else None
                    )
                ),
                "last_verified": (
                    c.last_verified.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if c.last_verified and c.last_verified.tzinfo
                    else (
                        c.last_verified.replace(tzinfo=timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                        if c.last_verified
                        else None
                    )
                )
                if c.last_verified
                else None,
                "sign_count": c.sign_count,
            }
        )
    from .. import aaguid as aaguid_mod

    aaguid_info = aaguid_mod.filter(aaguids)

    # Get sessions for the user
    normalized_request_host = hostutil.normalize_host(request.headers.get("host"))
    session_records = await db.instance.list_sessions_for_user(user_uuid)
    current_session_key = session_key(auth)
    sessions_payload: list[dict] = []
    for entry in session_records:
        sessions_payload.append(
            {
                "id": encode_session_key(entry.key),
                "host": entry.host,
                "ip": entry.ip,
                "user_agent": useragent.compact_user_agent(entry.user_agent),
                "last_renewed": (
                    entry.renewed.astimezone(timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if entry.renewed.tzinfo
                    else entry.renewed.replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                ),
                "is_current": entry.key == current_session_key,
                "is_current_host": bool(
                    normalized_request_host
                    and entry.host
                    and entry.host == normalized_request_host
                ),
            }
        )

    return {
        "display_name": user.display_name,
        "org": {"display_name": user_org.display_name},
        "role": role_name,
        "visits": user.visits,
        "created_at": (
            user.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if user.created_at and user.created_at.tzinfo
            else (
                user.created_at.replace(tzinfo=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
                if user.created_at
                else None
            )
        ),
        "last_seen": (
            user.last_seen.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if user.last_seen and user.last_seen.tzinfo
            else (
                user.last_seen.replace(tzinfo=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
                if user.last_seen
                else None
            )
        ),
        "credentials": creds,
        "aaguid_info": aaguid_info,
        "sessions": sessions_payload,
    }


@app.put("/orgs/{org_uuid}/users/{user_uuid}/display-name")
async def admin_update_user_display_name(
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    try:
        user_org, _role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if (
        "auth:admin" not in ctx.role.permissions
        and f"auth:org:{org_uuid}" not in ctx.role.permissions
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    new_name = (payload.get("display_name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name required")
    if len(new_name) > 64:
        raise HTTPException(status_code=400, detail="display_name too long")
    await db.instance.update_user_display_name(user_uuid, new_name)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/users/{user_uuid}/credentials/{credential_uuid}")
async def admin_delete_user_credential(
    org_uuid: UUID,
    user_uuid: UUID,
    credential_uuid: UUID,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    try:
        user_org, _role_name = await db.instance.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", f"auth:org:{org_uuid}"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if (
        "auth:admin" not in ctx.role.permissions
        and f"auth:org:{org_uuid}" not in ctx.role.permissions
    ):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    await db.instance.delete_credential(credential_uuid, user_uuid)
    return {"status": "ok"}


# -------------------- Permissions (global) --------------------


@app.get("/permissions")
async def admin_list_permissions(
    request: Request, auth=Cookie(None, alias="__Host-auth")
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:*"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    perms = await db.instance.list_permissions()

    # Global admins see all permissions
    if "auth:admin" in ctx.role.permissions:
        return [{"id": p.id, "display_name": p.display_name} for p in perms]

    # Org admins only see permissions their org can grant
    grantable = set(ctx.org.permissions or [])
    filtered_perms = [p for p in perms if p.id in grantable]
    return [{"id": p.id, "display_name": p.display_name} for p in filtered_perms]


@app.post("/permissions")
async def admin_create_permission(
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
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
    permission_id: str,
    display_name: str,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
    from ..db import Permission as PermDC

    if not display_name:
        raise ValueError("display_name is required")
    querysafe.assert_safe(permission_id, field="permission_id")
    await db.instance.update_permission(
        PermDC(id=permission_id, display_name=display_name)
    )
    return {"status": "ok"}


@app.post("/permission/rename")
async def admin_rename_permission(
    request: Request,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
    old_id = payload.get("old_id")
    new_id = payload.get("new_id")
    display_name = payload.get("display_name")
    if not old_id or not new_id:
        raise ValueError("old_id and new_id required")

    # Sanity check: prevent renaming critical permissions
    if old_id == "auth:admin":
        raise ValueError("Cannot rename the master admin permission")

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
async def admin_delete_permission(
    permission_id: str,
    request: Request,
    auth=Cookie(None, alias="__Host-auth"),
):
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )
    querysafe.assert_safe(permission_id, field="permission_id")

    # Sanity check: prevent deleting critical permissions
    if permission_id == "auth:admin":
        raise ValueError("Cannot delete the master admin permission")

    await db.instance.delete_permission(permission_id)
    return {"status": "ok"}
