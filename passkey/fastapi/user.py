from datetime import timezone
from uuid import UUID

from fastapi import (
    Body,
    Cookie,
    FastAPI,
    HTTPException,
    Request,
    Response,
)

from ..authsession import (
    delete_credential,
    expires,
    get_session,
)
from ..globals import db
from ..util import hostutil, passphrase, tokens
from ..util.tokens import decode_session_key, session_key
from . import session

app = FastAPI()


@app.put("/display-name")
async def user_update_display_name(
    request: Request,
    response: Response,
    payload: dict = Body(...),
    auth=Cookie(None, alias="__Host-auth"),
):
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication Required")
    try:
        s = await get_session(auth, host=request.headers.get("host"))
    except ValueError as e:
        raise HTTPException(status_code=401, detail="Session expired") from e
    new_name = (payload.get("display_name") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="display_name required")
    if len(new_name) > 64:
        raise HTTPException(status_code=400, detail="display_name too long")
    await db.instance.update_user_display_name(s.user_uuid, new_name)
    return {"status": "ok"}


@app.post("/logout-all")
async def api_logout_all(
    request: Request, response: Response, auth=Cookie(None, alias="__Host-auth")
):
    if not auth:
        return {"message": "Already logged out"}
    try:
        s = await get_session(auth, host=request.headers.get("host"))
    except ValueError:
        raise HTTPException(status_code=401, detail="Session expired")
    await db.instance.delete_sessions_for_user(s.user_uuid)
    session.clear_session_cookie(response)
    return {"message": "Logged out from all hosts"}


@app.delete("/session/{session_id}")
async def api_delete_session(
    request: Request,
    response: Response,
    session_id: str,
    auth=Cookie(None, alias="__Host-auth"),
):
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication Required")
    try:
        current_session = await get_session(auth, host=request.headers.get("host"))
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Session expired") from exc

    try:
        target_key = decode_session_key(session_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=400, detail="Invalid session identifier"
        ) from exc

    target_session = await db.instance.get_session(target_key)
    if not target_session or target_session.user_uuid != current_session.user_uuid:
        raise HTTPException(status_code=404, detail="Session not found")

    await db.instance.delete_session(target_key)
    current_terminated = target_key == session_key(auth)
    if current_terminated:
        session.clear_session_cookie(response)  # explicit because 200
    return {"status": "ok", "current_session_terminated": current_terminated}


@app.delete("/credential/{uuid}")
async def api_delete_credential(
    request: Request,
    response: Response,
    uuid: UUID,
    auth: str = Cookie(None, alias="__Host-auth"),
):
    try:
        await delete_credential(uuid, auth, host=request.headers.get("host"))
    except ValueError as e:
        raise HTTPException(status_code=401, detail="Session expired") from e
    return {"message": "Credential deleted successfully"}


@app.post("/create-link")
async def api_create_link(
    request: Request,
    response: Response,
    auth=Cookie(None, alias="__Host-auth"),
):
    try:
        s = await get_session(auth, host=request.headers.get("host"))
    except ValueError as e:
        raise HTTPException(status_code=401, detail="Session expired") from e
    token = passphrase.generate()
    expiry = expires()
    await db.instance.create_reset_token(
        user_uuid=s.user_uuid,
        key=tokens.reset_key(token),
        expiry=expiry,
        token_type="device addition",
    )
    url = hostutil.reset_link_url(
        token, request.url.scheme, request.headers.get("host")
    )
    return {
        "message": "Registration link generated successfully",
        "url": url,
        "expires": (
            expiry.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            if expiry.tzinfo
            else expiry.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        ),
    }
