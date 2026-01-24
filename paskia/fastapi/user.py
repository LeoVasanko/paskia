from datetime import timezone
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
    get_session,
)
from paskia.fastapi import authz, session
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import hostutil, passphrase

app = FastAPI()


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
    try:
        s = await get_session(auth, host=request.headers.get("host"))
    except ValueError as e:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        ) from e
    new_name = (payload.get("display_name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name required")
    if len(new_name) > 64:
        raise HTTPException(status_code=400, detail="display_name too long")
    db.update_user_display_name(s.user_uuid, new_name)
    return {"status": "ok"}


@app.post("/logout-all")
async def api_logout_all(request: Request, response: Response, auth=AUTH_COOKIE):
    if not auth:
        return {"message": "Already logged out"}
    try:
        s = await get_session(auth, host=request.headers.get("host"))
    except ValueError:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        )
    db.delete_sessions_for_user(s.user_uuid)
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
    try:
        current_session = await get_session(auth, host=request.headers.get("host"))
    except ValueError as exc:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        ) from exc

    target_session = db.get_session(session_id)
    if not target_session or target_session.user_uuid != current_session.user_uuid:
        raise HTTPException(status_code=404, detail="Session not found")

    db.delete_session(session_id)
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
        await delete_credential(uuid, auth, host=request.headers.get("host"))
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
    await authz.verify(auth, [], host=request.headers.get("host"), max_age="5m")
    try:
        s = await get_session(auth, host=request.headers.get("host"))
    except ValueError as e:
        raise authz.AuthException(
            status_code=401, detail="Session expired", mode="login"
        ) from e
    token = passphrase.generate()
    expiry = expires()
    db.create_reset_token(
        user_uuid=s.user_uuid,
        passphrase=token,
        expiry=expiry,
        token_type="device addition",
    )
    url = hostutil.reset_link_url(token)
    return {
        "message": "Registration link generated successfully",
        "url": url,
        "expires": (
            expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if expiry.tzinfo
            else expiry.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        ),
    }
