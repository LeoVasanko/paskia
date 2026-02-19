from uuid import UUID

from fastapi import Body, FastAPI, HTTPException, Request

from paskia import aaguid as aaguid_mod
from paskia import db
from paskia.authsession import reset_expires
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import hostutil, permutil
from paskia.util.apistructs import (
    ApiAaguidInfo,
    ApiCreateLinkResponse,
    ApiOrg,
    ApiRole,
    ApiUser,
    ApiUserDetail,
    ApiUserSession,
)

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


@app.patch("/{user_uuid}/role")
async def admin_update_user_role(
    user_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    role_uuid_str = payload.get("role_uuid")
    if not role_uuid_str:
        raise ValueError("role_uuid is required")
    try:
        new_role_uuid = UUID(role_uuid_str)
    except (ValueError, TypeError):
        raise ValueError("Invalid role UUID")
    new_role = db.data().roles.get(new_role_uuid)
    if not new_role or new_role.org_uuid != user.org.uuid:
        raise ValueError("Role not found in organization")

    # Sanity check: prevent admin from removing their own access
    if ctx.user.uuid == user_uuid:
        # Check if any permission in the new role is an admin permission
        has_admin_access = False
        for perm_uuid in new_role.permissions:
            perm = db.data().permissions.get(perm_uuid)
            if perm and perm.scope in ["auth:admin", "auth:org:admin"]:
                has_admin_access = True
                break
        if not has_admin_access:
            raise ValueError(
                "Cannot change your own role to one without admin permissions"
            )

    db.update_user_role(user_uuid, new_role_uuid, ctx=ctx)
    return {"status": "ok"}


@app.post("/{user_uuid}/create-link")
async def admin_create_user_registration_link(
    user_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    # Check if user has existing credentials
    has_credentials = db.data().users[user_uuid].credential_ids
    token_type = "user registration" if not has_credentials else "account recovery"

    expiry = reset_expires()
    token = db.create_reset_token(
        user_uuid=user_uuid,
        expiry=expiry,
        token_type=token_type,
        ctx=ctx,
    )
    url = hostutil.reset_link_url(token)
    return MsgspecResponse(
        ApiCreateLinkResponse(
            url=url,
            expires=expiry,
            token_type=token_type,
        )
    )


@app.get("/{user_uuid}")
async def admin_get_user_detail(
    user_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    normalized_host = hostutil.normalize_host(request.headers.get("host"))

    sessions = {
        s.key: ApiUserSession.from_db(
            s,
            current_key=ctx.session.key,
            normalized_host=normalized_host,
        )
        for s in user.sessions
    }

    return MsgspecResponse(
        ApiUserDetail(
            user=ApiUser.from_db(user),
            credentials={c.uuid: c for c in user.credentials},
            aaguid_info={
                k: ApiAaguidInfo(**v)
                for k, v in aaguid_mod.filter(
                    c.aaguid for c in user.credentials
                ).items()
            },
            sessions=sessions,
            org=ApiOrg.from_db(user.org),
            role=ApiRole.from_db(user.role),
        )
    )


@app.patch("/{user_uuid}/info")
async def admin_update_user_info(
    user_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update user profile info (display_name, email, preferred_username, telephone).

    Pass only the fields you want to update. Use null to clear optional fields.
    """
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    kwargs = {}
    if "display_name" in payload:
        name = (payload["display_name"] or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="display_name cannot be empty")
        if len(name) > 64:
            raise HTTPException(status_code=400, detail="display_name too long")
        kwargs["display_name"] = name
    if "email" in payload:
        kwargs["email"] = payload["email"]
    if "preferred_username" in payload:
        kwargs["preferred_username"] = payload["preferred_username"]
    if "telephone" in payload:
        kwargs["telephone"] = payload["telephone"]

    if not kwargs:
        raise HTTPException(status_code=400, detail="No fields to update")

    db.update_user_info(user_uuid, **kwargs, ctx=ctx)
    return {"status": "ok"}


@app.delete("/{user_uuid}")
async def admin_delete_user(
    user_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Delete a user and all their credentials/sessions."""
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    # Prevent admin from deleting themselves
    if ctx.user.uuid == user_uuid:
        raise ValueError("Cannot delete your own account")
    db.delete_user(user_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/{user_uuid}/credentials/{credential_uuid}")
async def admin_delete_user_credential(
    user_uuid: UUID,
    credential_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
        max_age="5m",
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )
    db.delete_credential(credential_uuid, user_uuid, ctx=ctx)
    return {"status": "ok"}


@app.delete("/{user_uuid}/sessions/{session_id}")
async def admin_delete_user_session(
    user_uuid: UUID,
    session_id: str,
    request: Request,
    auth=AUTH_COOKIE,
):
    try:
        user = db.data().users[user_uuid]
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )
    if not can_manage_org(ctx, user.org.uuid):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    session_key = session_id

    target_session = db.data().sessions.get(session_key)
    if not target_session or target_session.user_uuid != user_uuid:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete_session(session_key, ctx=ctx, action="admin:delete_session")

    # Check if admin terminated their own session
    current_terminated = session_key == ctx.session.key
    return {"status": "ok", "current_session_terminated": current_terminated}
