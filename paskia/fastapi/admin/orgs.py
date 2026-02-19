from uuid import UUID

from fastapi import Body, FastAPI, HTTPException, Query, Request

from paskia import db
from paskia.db import Org as OrgDC
from paskia.db import Role as RoleDC
from paskia.db import User as UserDC
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import permutil
from paskia.util.apistructs import ApiUuidResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

install_error_handlers(app)


def master_admin(ctx) -> bool:
    return any(p.scope == "auth:admin" for p in ctx.permissions)


def org_admin(ctx, org_uuid: UUID) -> bool:
    return ctx.org.uuid == org_uuid and any(
        p.scope == "auth:org:admin" for p in ctx.permissions
    )


def can_manage_org(ctx, org_uuid: UUID) -> bool:
    return master_admin(ctx) or org_admin(ctx, org_uuid)


@app.post("/")
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
        db.add_permission_to_org(str(org.uuid), perm, ctx=ctx)

    return MsgspecResponse(ApiUuidResponse(uuid=str(org.uuid)))


@app.patch("/{org_uuid}")
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


@app.delete("/{org_uuid}")
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


@app.post("/{org_uuid}/permission")
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


@app.delete("/{org_uuid}/permission")
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


@app.post("/{org_uuid}/roles")
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
    org = db.data().orgs[org_uuid]
    grantable = {p.uuid for p in org.permissions}

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
    return MsgspecResponse(ApiUuidResponse(uuid=str(role.uuid)))


@app.post("/{org_uuid}/users")
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

    org = db.data().orgs[org_uuid]
    role_obj = next(
        (r for r in org.roles if r.display_name == role_name),
        None,
    )
    if not role_obj:
        raise ValueError("Role not found in organization")
    user = UserDC.create(
        display_name=display_name,
        role=role_obj.uuid,
    )
    db.create_user(user, ctx=ctx)
    return MsgspecResponse(ApiUuidResponse(uuid=str(user.uuid)))
