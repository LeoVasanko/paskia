from uuid import UUID

from fastapi import (
    Body,
    FastAPI,
    File,
    HTTPException,
    Request,
    Response,
    UploadFile,
)
from fastapi.responses import FileResponse, JSONResponse

from paskia import db
from paskia.authsession import (
    delete_credential,
    expires,
    session_ctx,
)
from paskia.fastapi import authz, session
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import avatar, hostutil
from paskia.util.apistructs import ApiCreateLinkResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _can_manage_avatar(ctx, target_user) -> bool:
    if ctx.user.uuid == target_user.uuid:
        return True

    if any(p.scope == "auth:admin" for p in ctx.permissions):
        return True

    return ctx.org.uuid == target_user.org.uuid and any(
        p.scope == "auth:org:admin" for p in ctx.permissions
    )


def _avatar_write_ctx(request: Request, user_uuid: UUID, auth):
    if not auth:
        raise authz.AuthException(
            status_code=401, detail="Authentication Required", mode="login"
        )

    ctx = session_ctx(auth, request.headers.get("host"))
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )

    user = db.data().users.get(user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="Avatar not found")

    if not _can_manage_avatar(ctx, user):
        raise authz.AuthException(
            status_code=403, detail="Insufficient permissions", mode="forbidden"
        )

    return ctx, user


@app.exception_handler(authz.AuthException)
async def auth_exception_handler(_request, exc: authz.AuthException):
    """Handle AuthException with auth info for UI."""
    return JSONResponse(
        status_code=exc.status_code,
        content=await authz.auth_error_content(exc),
    )


@app.patch("/display-name")
async def user_update_display_name(
    request: Request,
    response: Response,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update display name only. Used by registration flow (auto-fills preferred_username)."""
    if not auth:
        raise authz.AuthException(
            status_code=401, detail="Authentication Required", mode="login"
        )
    host = request.headers.get("host")
    ctx = session_ctx(auth, host)
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )
    new_name = (payload.get("display_name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name required")
    if len(new_name) > 64:
        raise HTTPException(status_code=400, detail="display_name too long")
    db.update_user_display_name(ctx.user.uuid, new_name, ctx=ctx)
    return {"status": "ok"}


@app.patch("/info")
async def user_update_info(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update user profile info (display_name, email, preferred_username, telephone).

    Pass only the fields you want to update. Use null to clear optional fields.
    Does NOT auto-fill preferred_username (unlike /display-name endpoint).
    """
    if not auth:
        raise authz.AuthException(
            status_code=401, detail="Authentication Required", mode="login"
        )
    ctx = session_ctx(auth, request.headers.get("host"))
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
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

    db.update_user_info(ctx.user.uuid, **kwargs, ctx=ctx)
    return {"status": "ok"}


@app.get("/{user_uuid}/profile.webp")
async def serve_avatar(request: Request, user_uuid: UUID):
    """Serve a user's current avatar with short-lived caching and ETag."""
    user = db.data().users.get(user_uuid)
    if not user:
        raise HTTPException(status_code=404, detail="Avatar not found")

    path = avatar.avatar_path(user_uuid)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Avatar not found")

    data = avatar.read_avatar_bytes(user_uuid)
    if data is None:
        raise HTTPException(status_code=404, detail="Avatar not found")

    etag = avatar.avatar_etag(data)
    if request.headers.get("if-none-match") == f'"{etag}"':
        return Response(status_code=304, headers={"ETag": f'"{etag}"'})

    headers = {
        "ETag": f'"{etag}"',
        "Cache-Control": "public, max-age=300",
    }

    return FileResponse(path, media_type="image/webp", headers=headers)


@app.put("/{user_uuid}/profile.webp")
async def upload_avatar(
    request: Request,
    user_uuid: UUID,
    file: UploadFile = File(...),
    auth=AUTH_COOKIE,
):
    """Upload a user's browser-prepared WebP avatar on the same URL it is served from."""
    _ctx, _user = _avatar_write_ctx(request, user_uuid, auth)
    data = await avatar.read_upload(file)
    avatar.store_avatar(user_uuid, data)
    return {"status": "ok", "avatar_url": avatar.avatar_browser_url(user_uuid)}


@app.delete("/{user_uuid}/profile.webp")
async def delete_avatar(request: Request, user_uuid: UUID, auth=AUTH_COOKIE):
    """Delete a user's avatar image on the same URL it is served from."""
    _ctx, _user = _avatar_write_ctx(request, user_uuid, auth)
    avatar.remove_avatar_file(user_uuid)
    return {"status": "ok"}


@app.patch("/theme")
async def user_update_theme(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    if not auth:
        raise authz.AuthException(
            status_code=401, detail="Authentication Required", mode="login"
        )
    ctx = session_ctx(auth, request.headers.get("host"))
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )
    theme = payload.get("theme", "")
    if theme not in ("", "light", "dark"):
        raise HTTPException(status_code=400, detail="Invalid theme")
    db.update_user_info(ctx.user.uuid, theme=theme, ctx=ctx)
    return {"status": "ok"}


@app.post("/logout-all")
async def api_logout_all(request: Request, response: Response, auth=AUTH_COOKIE):
    if not auth:
        return {"message": "Already logged out"}
    host = request.headers.get("host")
    ctx = session_ctx(auth, host)
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )
    db.delete_sessions_for_user(ctx.user.uuid, ctx=ctx)
    session.clear_session_cookie(response)
    return {"message": "Logged out from all hosts"}


@app.delete("/session/{session_id}")
async def api_delete_session(
    request: Request,
    response: Response,
    session_id: str,
    auth=AUTH_COOKIE,
):
    if not auth:
        raise authz.AuthException(
            status_code=401, detail="Authentication Required", mode="login"
        )
    host = request.headers.get("host")
    ctx = session_ctx(auth, host)
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )

    session_key = session_id

    target_session = db.data().sessions.get(session_key)
    if not target_session or target_session.user_uuid != ctx.user.uuid:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete_session(session_key, ctx=ctx)
    current_terminated = session_key == ctx.session.key
    if current_terminated:
        session.clear_session_cookie(response)  # explicit because 200
    return {"status": "ok", "current_session_terminated": current_terminated}


@app.delete("/credential/{uuid}")
async def api_delete_credential(
    request: Request,
    response: Response,
    uuid: UUID,
    auth: str = AUTH_COOKIE,
):
    # Require recent authentication for sensitive operation
    await authz.verify(auth, [], host=request.headers.get("host"), max_age="5m")
    try:
        delete_credential(uuid, auth, host=request.headers.get("host"))
    except ValueError as e:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        ) from e
    return {"message": "Credential deleted successfully"}


@app.post("/create-link")
async def api_create_link(
    request: Request,
    response: Response,
    auth=AUTH_COOKIE,
):
    # Require recent authentication for sensitive operation
    ctx = await authz.verify(auth, [], host=request.headers.get("host"), max_age="5m")
    expiry = expires()
    token = db.create_reset_token(
        user_uuid=ctx.user.uuid,
        expiry=expiry,
        token_type="device addition",
        ctx=ctx,
    )
    url = hostutil.reset_link_url(token)
    return MsgspecResponse(
        ApiCreateLinkResponse(
            message="Registration link generated successfully",
            url=url,
            expires=expiry,
            token_type="device addition",
        )
    )
