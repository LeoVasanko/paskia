import logging
from datetime import timezone
from uuid import UUID

from fastapi import Body, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from paskia import aaguid as aaguid_mod
from paskia import db
from paskia.authsession import EXPIRES, reset_expires
from paskia.db import Org as OrgDC
from paskia.db import Permission as PermDC
from paskia.db import Role as RoleDC
from paskia.db import User as UserDC
from paskia.fastapi import authz
from paskia.fastapi.session import AUTH_COOKIE
from paskia.globals import passkey
from paskia.util import (
    hostutil,
    passphrase,
    permutil,
    querysafe,
    useragent,
    vitedev,
)
from paskia.util.hostutil import normalize_host

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def is_global_admin(ctx) -> bool:
    """Check if user has global admin permission."""
    effective_scopes = (
        {p.scope for p in (ctx.permissions or [])}
        if ctx.permissions
        else set(ctx.role.permissions or [])
    )
    return "auth:admin" in effective_scopes


def is_org_admin(ctx, org_uuid: UUID | None = None) -> bool:
    """Check if user has org admin permission.

    If org_uuid is provided, checks if user is admin of that specific org.
    If org_uuid is None, checks if user is admin of their own org.
    """
    effective_scopes = (
        {p.scope for p in (ctx.permissions or [])}
        if ctx.permissions
        else set(ctx.role.permissions or [])
    )
    if "auth:org:admin" not in effective_scopes:
        return False
    if org_uuid is None:
        return True
    # User must belong to the target org (via their role)
    return ctx.org.uuid == org_uuid


def can_manage_org(ctx, org_uuid: UUID) -> bool:
    """Check if user can manage the specified organization."""
    return is_global_admin(ctx) or is_org_admin(ctx, org_uuid)


@app.exception_handler(ValueError)
async def value_error_handler(_request, exc: ValueError):  # pragma: no cover - simple
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(authz.AuthException)
async def auth_exception_handler(_request, exc: authz.AuthException):
    """Handle AuthException with auth info for UI."""
    return JSONResponse(
        status_code=exc.status_code,
        content=await authz.auth_error_content(exc),
    )


@app.exception_handler(Exception)
async def general_exception_handler(_request, exc: Exception):  # pragma: no cover
    logging.exception("Unhandled exception in admin app")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/")
async def adminapp(request: Request, auth=AUTH_COOKIE):
    return Response(*await vitedev.read("/auth/admin/index.html"))


# -------------------- Organizations --------------------


@app.get("/orgs")
async def admin_list_orgs(request: Request, auth=AUTH_COOKIE):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    orgs = list(db.data().orgs.values())
    if not is_global_admin(ctx):
        # Org admins can only see their own organization
        orgs = [o for o in orgs if o.uuid == ctx.org.uuid]

    def role_to_dict(r):
        return {
            "uuid": str(r.uuid),
            "org": str(r.org),
            "display_name": r.display_name,
            "permissions": list(r.permissions.keys()),
        }

    async def org_to_dict(o):
        users = db.get_organization_users(o.uuid)
        return {
            "uuid": str(o.uuid),
            "display_name": o.display_name,
            "permissions": {
                pid for pid, p in db.data().permissions.items() if o.uuid in p.orgs
            },
            "roles": [
                role_to_dict(r) for r in db.data().roles.values() if r.org == o.uuid
            ],
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
    request: Request, payload: dict = Body(...), auth=AUTH_COOKIE
):
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )

    display_name = payload.get("display_name") or "New Organization"
    permissions = payload.get("permissions") or []
    org = OrgDC.create(display_name=display_name)
    db.create_org(org, ctx=ctx)
    # Grant requested permissions to the new org
    for perm in permissions:
        db.add_permission_to_org(str(org.uuid), perm)

    return {"uuid": str(org.uuid)}


@app.patch("/orgs/{org_uuid}")
async def admin_update_org_name(
    org_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update organization display name only."""
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    display_name = payload.get("display_name")
    if not display_name:
        raise ValueError("display_name is required")

    db.update_org_name(org_uuid, display_name, ctx=ctx)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}")
async def admin_delete_org(org_uuid: UUID, request: Request, auth=AUTH_COOKIE):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    if ctx.org.uuid == org_uuid:
        raise ValueError("Cannot delete the organization you belong to")

    # Delete organization-specific permissions
    org_perm_pattern = f"org:{str(org_uuid).lower()}"
    all_permissions = list(db.data().permissions.values())
    for perm in all_permissions:
        perm_scope_lower = perm.scope.lower()
        # Check if permission contains "org:{uuid}" separated by colons or at boundaries
        if (
            f":{org_perm_pattern}:" in perm_scope_lower
            or perm_scope_lower.startswith(f"{org_perm_pattern}:")
            or perm_scope_lower.endswith(f":{org_perm_pattern}")
            or perm_scope_lower == org_perm_pattern
        ):
            db.delete_permission(perm.uuid, ctx=ctx)

    db.delete_org(org_uuid, ctx=ctx)
    return {"status": "ok"}


@app.post("/orgs/{org_uuid}/permission")
async def admin_add_org_permission(
    org_uuid: UUID,
    request: Request,
    permission_uuid: UUID = Query(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )

    db.add_permission_to_org(org_uuid, permission_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/permission")
async def admin_remove_org_permission(
    org_uuid: UUID,
    request: Request,
    permission_uuid: UUID = Query(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )

    db.remove_permission_from_org(org_uuid, permission_uuid, ctx=ctx)

    # Guard rail: prevent removing auth:admin from your own org if it would lock you out
    perm = db.data().permissions.get(permission_uuid)
    if perm and perm.scope == "auth:admin" and ctx.org.uuid == org_uuid:
        # Check if any other org grants auth:admin that we're a member of
        # (we only know our current org, so this effectively means we can't remove it from our own org)
        raise ValueError(
            "Cannot remove auth:admin from your own organization. "
            "This would lock you out of admin access."
        )

    db.remove_permission_from_org(org_uuid, permission_uuid, ctx=ctx)
    return {"status": "ok"}


# -------------------- Roles --------------------


@app.post("/orgs/{org_uuid}/roles")
async def admin_create_role(
    org_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    display_name = payload.get("display_name") or "New Role"
    perms = payload.get("permissions") or []
    if org_uuid not in db.data().orgs:
        raise HTTPException(status_code=404, detail="Organization not found")
    grantable = {pid for pid, p in db.data().permissions.items() if org_uuid in p.orgs}

    # Normalize permission IDs to UUIDs
    permission_uuids: set[UUID] = set()
    for pid in perms:
        perm = db.data().permissions.get(UUID(pid))
        if not perm:
            raise ValueError(f"Permission {pid} not found")
        if perm.uuid not in grantable:
            raise ValueError(f"Permission not grantable by org: {pid}")
        permission_uuids.add(perm.uuid)

    role = RoleDC.create(
        org=org_uuid,
        display_name=display_name,
        permissions=permission_uuids,
    )
    db.create_role(role, ctx=ctx)
    return {"uuid": str(role.uuid)}


@app.patch("/orgs/{org_uuid}/roles/{role_uuid}")
async def admin_update_role_name(
    org_uuid: UUID,
    role_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update role display name only."""
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    role = db.data().roles.get(role_uuid)
    if not role or role.org != org_uuid:
        raise HTTPException(status_code=404, detail="Role not found in organization")

    display_name = payload.get("display_name")
    if not display_name:
        raise ValueError("display_name is required")

    db.update_role_name(role_uuid, display_name, ctx=ctx)
    return {"status": "ok"}


@app.post("/orgs/{org_uuid}/roles/{role_uuid}/permissions/{permission_uuid}")
async def admin_add_role_permission(
    org_uuid: UUID,
    role_uuid: UUID,
    permission_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Add a permission to a role (intent-based API)."""
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    role = db.data().roles.get(role_uuid)
    if not role or role.org != org_uuid:
        raise HTTPException(status_code=404, detail="Role not found in organization")

    # Verify permission exists and org can grant it
    perm = db.data().permissions.get(permission_uuid)
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if org_uuid not in perm.orgs:
        raise ValueError("Permission not grantable by organization")

    db.add_permission_to_role(role_uuid, permission_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/roles/{role_uuid}/permissions/{permission_uuid}")
async def admin_remove_role_permission(
    org_uuid: UUID,
    role_uuid: UUID,
    permission_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Remove a permission from a role (intent-based API)."""
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    role = db.data().roles.get(role_uuid)
    if not role or role.org != org_uuid:
        raise HTTPException(status_code=404, detail="Role not found in organization")

    # Sanity check: prevent admin from removing their own access
    perm = db.data().permissions.get(permission_uuid)
    if ctx.org.uuid == org_uuid and ctx.role.uuid == role_uuid:
        if perm and perm.scope in ["auth:admin", "auth:org:admin"]:
            # Check if removing this permission would leave no admin access
            remaining_perms = role.permission_set - {permission_uuid}
            has_admin = False
            for rp_uuid in remaining_perms:
                rp = db.data().permissions.get(rp_uuid)
                if rp and rp.scope in ["auth:admin", "auth:org:admin"]:
                    has_admin = True
                    break
            if not has_admin:
                raise ValueError("Cannot remove your own admin permissions")

    db.remove_permission_from_role(role_uuid, permission_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/roles/{role_uuid}")
async def admin_delete_role(
    org_uuid: UUID,
    role_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    role = db.data().roles.get(role_uuid)
    if not role or role.org != org_uuid:
        raise HTTPException(status_code=404, detail="Role not found in organization")

    # Sanity check: prevent admin from deleting their own role
    if ctx.role.uuid == role_uuid:
        raise ValueError("Cannot delete your own role")

    db.delete_role(role_uuid, ctx=ctx)
    return {"status": "ok"}


# -------------------- Users --------------------


@app.post("/orgs/{org_uuid}/users")
async def admin_create_user(
    org_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    display_name = payload.get("display_name")
    role_name = payload.get("role")
    if not display_name or not role_name:
        raise ValueError("display_name and role are required")

    roles = [r for r in db.data().roles.values() if r.org == org_uuid]
    role_obj = next((r for r in roles if r.display_name == role_name), None)
    if not role_obj:
        raise ValueError("Role not found in organization")
    user = UserDC.create(
        display_name=display_name,
        role=role_obj.uuid,
    )
    db.create_user(user, ctx=ctx)
    return {"uuid": str(user.uuid)}


@app.patch("/orgs/{org_uuid}/users/{user_uuid}/role")
async def admin_update_user_role(
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    new_role = payload.get("role")
    if not new_role:
        raise ValueError("role is required")
    try:
        user_org, _current_role = db.get_user_organization(user_uuid)
    except ValueError:
        raise ValueError("User not found")
    if user_org.uuid != org_uuid:
        raise ValueError("User does not belong to this organization")
    roles = [r for r in db.data().roles.values() if r.org == org_uuid]
    if not any(r.display_name == new_role for r in roles):
        raise ValueError("Role not found in organization")

    # Sanity check: prevent admin from removing their own access
    if ctx.user.uuid == user_uuid:
        new_role_obj = next((r for r in roles if r.display_name == new_role), None)
        if new_role_obj:  # pragma: no branch - always true, role validated above
            # Check if any permission in the new role is an admin permission
            has_admin_access = False
            for perm_uuid in new_role_obj.permissions:
                perm = db.data().permissions.get(perm_uuid)
                if perm and perm.scope in ["auth:admin", "auth:org:admin"]:
                    has_admin_access = True
                    break
            if not has_admin_access:
                raise ValueError(
                    "Cannot change your own role to one without admin permissions"
                )

    db.update_user_role_in_organization(user_uuid, new_role, ctx=ctx)
    return {"status": "ok"}


@app.post("/orgs/{org_uuid}/users/{user_uuid}/create-link")
async def admin_create_user_registration_link(
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user_org, _role_name = db.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    # Check if user has existing credentials
    has_credentials = db.get_user_credential_ids(user_uuid)
    token_type = "user registration" if not has_credentials else "account recovery"

    token = passphrase.generate()
    expiry = reset_expires()
    db.create_reset_token(
        user_uuid=user_uuid,
        passphrase=token,
        expiry=expiry,
        token_type=token_type,
        ctx=ctx,
    )
    url = hostutil.reset_link_url(token)
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
    auth=AUTH_COOKIE,
):
    try:
        user_org, role_name = db.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    user = db.data().users.get(user_uuid)
    user_creds = [c for c in db.data().credentials.values() if c.user == user_uuid]
    creds: list[dict] = []
    aaguids: set[str] = set()
    for c in user_creds:
        aaguid_str = str(c.aaguid)
        aaguids.add(aaguid_str)
        creds.append(
            {
                "credential": str(c.uuid),
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

    aaguid_info = aaguid_mod.filter(aaguids)

    # Get sessions for the user
    normalized_request_host = hostutil.normalize_host(request.headers.get("host"))
    session_records = [s for s in db.data().sessions.values() if s.user == user_uuid]
    current_session_key = auth
    sessions_payload: list[dict] = []
    for entry in session_records:
        renewed = entry.expiry - EXPIRES
        sessions_payload.append(
            {
                "id": entry.key,
                "credential": str(entry.credential),
                "host": entry.host,
                "ip": entry.ip,
                "user_agent": useragent.compact_user_agent(entry.user_agent),
                "last_renewed": (
                    renewed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                    if renewed.tzinfo
                    else renewed.replace(tzinfo=timezone.utc)
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


@app.patch("/orgs/{org_uuid}/users/{user_uuid}/display-name")
async def admin_update_user_display_name(
    org_uuid: UUID,
    user_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    try:
        user_org, _role_name = db.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    new_name = (payload.get("display_name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name required")
    if len(new_name) > 64:
        raise HTTPException(status_code=400, detail="display_name too long")
    db.update_user_display_name(user_uuid, new_name, ctx=ctx)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/users/{user_uuid}/credentials/{credential_uuid}")
async def admin_delete_user_credential(
    org_uuid: UUID,
    user_uuid: UUID,
    credential_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user_org, _role_name = db.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    db.delete_credential(credential_uuid, user_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/orgs/{org_uuid}/users/{user_uuid}/sessions/{session_id}")
async def admin_delete_user_session(
    org_uuid: UUID,
    user_uuid: UUID,
    session_id: str,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user_org, _role_name = db.get_user_organization(user_uuid)
    except ValueError:
        raise HTTPException(status_code=404, detail="User not found")
    if user_org.uuid != org_uuid:
        raise HTTPException(status_code=404, detail="User not found in organization")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    target_session = db.data().sessions.get(session_id)
    if not target_session or target_session.user != user_uuid:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete_session(session_id, ctx=ctx)

    # Check if admin terminated their own session
    current_terminated = session_id == auth
    return {"status": "ok", "current_session_terminated": current_terminated}


# -------------------- Permissions (global) --------------------


def _perm_to_dict(p):
    """Convert Permission to dict, omitting domain if None."""
    d = {"uuid": str(p.uuid), "scope": p.scope, "display_name": p.display_name}
    if p.domain is not None:
        d["domain"] = p.domain
    return d


def _validate_permission_domain(domain: str | None) -> None:
    """Validate that domain is rp_id or a subdomain of it."""
    if domain is None:
        return

    rp_id = passkey.instance.rp_id
    if domain == rp_id or domain.endswith(f".{rp_id}"):
        return
    raise ValueError(f"Domain '{domain}' must be '{rp_id}' or its subdomain")


def _check_admin_lockout(
    perm_uuid: str, new_domain: str | None, current_host: str | None
) -> None:
    """Check if setting domain on auth:admin would lock out the admin.

    Raises ValueError if this change would result in no auth:admin permissions
    being accessible from the current host.
    """

    normalized_host = normalize_host(current_host)
    host_without_port = normalized_host.rsplit(":", 1)[0] if normalized_host else None

    # Get all auth:admin permissions
    all_perms = list(db.data().permissions.values())
    admin_perms = [p for p in all_perms if p.scope == "auth:admin"]

    # Check if at least one auth:admin would remain accessible
    for p in admin_perms:
        # If this is the permission being modified, use the new domain
        domain = new_domain if str(p.uuid) == perm_uuid else p.domain

        # No domain restriction = accessible from anywhere
        if domain is None:
            return

        # Domain matches current host
        if host_without_port and domain == host_without_port:
            return

    # No accessible auth:admin permission would remain
    raise ValueError(
        "Cannot set this domain restriction: it would lock you out of admin access. "
        "Ensure at least one auth:admin permission remains accessible from your current host."
    )


def _check_admin_lockout_on_delete(perm_uuid: str, current_host: str | None) -> None:
    """Check if deleting an auth:admin permission would lock out the admin.

    Raises ValueError if this deletion would result in no auth:admin permissions
    being accessible from the current host.
    """

    normalized_host = normalize_host(current_host)
    host_without_port = normalized_host.rsplit(":", 1)[0] if normalized_host else None

    # Get all auth:admin permissions
    all_perms = list(db.data().permissions.values())
    admin_perms = [p for p in all_perms if p.scope == "auth:admin"]

    # Check if at least one auth:admin would remain accessible after deletion
    for p in admin_perms:
        # Skip the permission being deleted
        if str(p.uuid) == perm_uuid:
            continue

        # No domain restriction = accessible from anywhere
        if p.domain is None:
            return

        # Domain matches current host
        if host_without_port and p.domain == host_without_port:
            return

    # No accessible auth:admin permission would remain
    raise ValueError(
        "Cannot delete this permission: it would lock you out of admin access. "
        "Ensure at least one auth:admin permission remains accessible from your current host."
    )


@app.get("/permissions")
async def admin_list_permissions(request: Request, auth=AUTH_COOKIE):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    perms = list(db.data().permissions.values())

    # Global admins see all permissions
    if is_global_admin(ctx):
        return [_perm_to_dict(p) for p in perms]

    # Org admins only see permissions their org can grant (by UUID)
    grantable = {
        pid for pid, p in db.data().permissions.items() if ctx.org.uuid in p.orgs
    }
    filtered_perms = [p for p in perms if p.uuid in grantable]
    return [_perm_to_dict(p) for p in filtered_perms]


@app.post("/permissions")
async def admin_create_permission(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )

    scope = payload.get("scope") or payload.get(
        "id"
    )  # Support both for backwards compat
    display_name = payload.get("display_name")
    domain = payload.get("domain") or None  # Treat empty string as None
    if not scope or not display_name:
        raise ValueError("scope and display_name are required")
    querysafe.assert_safe(scope, field="scope")
    _validate_permission_domain(domain)
    db.create_permission(
        PermDC.create(scope=scope, display_name=display_name, domain=domain),
        ctx=ctx,
    )
    return {"status": "ok"}


@app.patch("/permission")
async def admin_update_permission(
    request: Request,
    auth=AUTH_COOKIE,
    permission_uuid: UUID = Query(...),
    display_name: str | None = Query(None),
    scope: str | None = Query(None),
    domain: str | None = Query(None),
):
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )

    # Get existing permission
    perm = db.data().permissions.get(permission_uuid)

    # Update fields that were provided
    new_scope = scope if scope is not None else perm.scope
    new_display_name = display_name if display_name is not None else perm.display_name
    domain_value = domain if domain else None

    # Sanity check: prevent changing the auth:admin permission scope
    if perm.scope == "auth:admin" and new_scope != "auth:admin":
        raise ValueError("Cannot rename the master admin permission")

    if not new_display_name:
        raise ValueError("display_name is required")
    querysafe.assert_safe(new_scope, field="scope")
    _validate_permission_domain(domain_value)

    # Safety check: prevent admin lockout when setting domain on auth:admin
    if perm.scope == "auth:admin" or new_scope == "auth:admin":
        _check_admin_lockout(str(perm.uuid), domain_value, request.headers.get("host"))

    db.update_permission(
        uuid=perm.uuid,
        scope=new_scope,
        display_name=new_display_name,
        domain=domain_value,
        ctx=ctx,
    )
    return {"status": "ok"}


@app.delete("/permission")
async def admin_delete_permission(
    request: Request,
    permission_uuid: UUID = Query(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )

    # Get the permission to check its scope
    perm = db.data().permissions.get(permission_uuid)

    # Sanity check: prevent deleting critical permissions if it would lock out admin
    if perm.scope == "auth:admin":
        _check_admin_lockout_on_delete(str(perm.uuid), request.headers.get("host"))

    db.delete_permission(permission_uuid, ctx=ctx)
    return {"status": "ok"}
