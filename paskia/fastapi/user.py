from datetime import UTC
from uuid import UUID

from fastapi import (
    Body,
    FastAPI,
    HTTPException,
    Request,
    Response,
)
from fastapi.responses import JSONResponse

from paskia import db
from paskia.authsession import (
    delete_credential,
    expires,
)
from paskia.fastapi import authz, session
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import hostutil, passphrase

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


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
    if not auth:
        raise authz.AuthException(
            status_code=401, detail="Authentication Required", mode="login"
        )
    host = request.headers.get("host")
    ctx = db.data().session_ctx(auth, host)
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
    ctx = db.data().session_ctx(auth, request.headers.get("host"))
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )
    theme = payload.get("theme", "")
    if theme not in ("", "light", "dark"):
        raise HTTPException(status_code=400, detail="Invalid theme")
    db.update_user_theme(ctx.user.uuid, theme, ctx=ctx)
    return {"status": "ok"}


@app.post("/logout-all")
async def api_logout_all(request: Request, response: Response, auth=AUTH_COOKIE):
    if not auth:
        return {"message": "Already logged out"}
    host = request.headers.get("host")
    ctx = db.data().session_ctx(auth, host)
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
    ctx = db.data().session_ctx(auth, host)
    if not ctx:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )

    target_session = db.data().sessions.get(session_id)
    if not target_session or target_session.user_uuid != ctx.user.uuid:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete_session(session_id, ctx=ctx)
    current_terminated = session_id == auth
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
    token = passphrase.generate()
    expiry = expires()
    db.create_reset_token(
        user_uuid=ctx.user.uuid,
        passphrase=token,
        expiry=expiry,
        token_type="device addition",
        ctx=ctx,
    )
    url = hostutil.reset_link_url(token)
    return {
        "message": "Registration link generated successfully",
        "url": url,
        "expires": (
            expiry.astimezone(UTC).isoformat().replace("+00:00", "Z")
            if expiry.tzinfo
            else expiry.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        ),
    }
