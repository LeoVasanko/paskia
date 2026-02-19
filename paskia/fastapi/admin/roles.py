from uuid import UUID

from fastapi import Body, FastAPI, HTTPException, Request

from paskia import db
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import permutil

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


@app.patch("/{role_uuid}")
async def admin_update_role_name(
    role_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update role display name only."""
    role = db.data().roles.get(role_uuid)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, role.org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    display_name = payload.get("display_name")
    if not display_name:
        raise ValueError("display_name is required")

    db.update_role_name(role_uuid, display_name, ctx=ctx)
    return {"status": "ok"}


@app.post("/{role_uuid}/permissions/{permission_uuid}")
async def admin_add_role_permission(
    role_uuid: UUID,
    permission_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Add a permission to a role (intent-based API)."""
    role = db.data().roles.get(role_uuid)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, role.org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    # Verify permission exists and org can grant it
    perm = db.data().permissions.get(permission_uuid)
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    if role.org_uuid not in perm.orgs:
        raise ValueError("Permission not grantable by organization")

    db.add_permission_to_role(role_uuid, permission_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/{role_uuid}/permissions/{permission_uuid}")
async def admin_remove_role_permission(
    role_uuid: UUID,
    permission_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Remove a permission from a role (intent-based API)."""
    role = db.data().roles.get(role_uuid)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, role.org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    # Sanity check: prevent admin from removing their own access
    perm = db.data().permissions.get(permission_uuid)
    if ctx.org.uuid == role.org_uuid and ctx.role.uuid == role_uuid:
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


@app.delete("/{role_uuid}")
async def admin_delete_role(
    role_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    role = db.data().roles.get(role_uuid)
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, role.org_uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    # Sanity check: prevent admin from deleting their own role
    if ctx.role.uuid == role_uuid:
        raise ValueError("Cannot delete your own role")

    db.delete_role(role_uuid, ctx=ctx)
    return {"status": "ok"}
