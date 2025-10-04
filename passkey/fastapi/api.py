import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import (
    Body,
    Cookie,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from passkey.util import frontend, useragent

from .. import aaguid
from ..authsession import (
    EXPIRES,
    delete_credential,
    expires,
    get_reset,
    get_session,
    refresh_session_token,
    session_expiry,
)
from ..globals import db
from ..globals import passkey as global_passkey
from ..util import hostutil, passphrase, permutil, tokens
from ..util.tokens import decode_session_key, encode_session_key, session_key
from . import authz, session

bearer_auth = HTTPBearer(auto_error=True)

app = FastAPI()


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException):
    """Ensure auth cookie is cleared on 401 responses (JSON responses only)."""
    if exc.status_code == 401:
        resp = JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        session.clear_session_cookie(resp)
        return resp
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


# Refresh only if at least this much of the session lifetime has been *consumed*.
# Consumption is derived from (now + EXPIRES) - current_expires.
# This guarantees a minimum spacing between DB writes even with frequent /validate calls.
_REFRESH_INTERVAL = timedelta(minutes=5)


@app.exception_handler(ValueError)
async def value_error_handler(_request: Request, exc: ValueError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def general_exception_handler(_request: Request, exc: Exception):
    logging.exception("Unhandled exception in API app")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.post("/validate")
async def validate_token(
    request: Request,
    response: Response,
    perm: list[str] = Query([]),
    auth=Cookie(None, alias="__Host-auth"),
):
    """Validate the current session and extend its expiry.

    Always refreshes the session (sliding expiration) and re-sets the cookie with a
    renewed max-age. This keeps active users logged in without needing a separate
    refresh endpoint.
    """
    try:
        ctx = await authz.verify(auth, perm, host=request.headers.get("host"))
    except HTTPException:
        # Global handler will clear cookie if 401
        raise
    renewed = False
    if auth:
        current_expiry = session_expiry(ctx.session)
        consumed = EXPIRES - (current_expiry - datetime.now())
        if not timedelta(0) < consumed < _REFRESH_INTERVAL:
            try:
                await refresh_session_token(
                    auth,
                    ip=request.client.host if request.client else "",
                    user_agent=request.headers.get("user-agent") or "",
                )
                session.set_session_cookie(response, auth)
                renewed = True
            except ValueError:
                # Session disappeared, e.g. due to concurrent logout; global handler will clear
                raise HTTPException(status_code=401, detail="Session expired")
    return {
        "valid": True,
        "user_uuid": str(ctx.session.user_uuid),
        "renewed": renewed,
    }


@app.get("/forward")
async def forward_authentication(
    request: Request,
    response: Response,
    perm: list[str] = Query([]),
    auth=Cookie(None, alias="__Host-auth"),
):
    """Forward auth validation for Caddy/Nginx.

    Query Params:
    - perm: repeated permission IDs the authenticated user must possess (ALL required).

    Success: 204 No Content with Remote-* headers describing the authenticated user.
    Failure (unauthenticated / unauthorized): 4xx JSON body with detail.
    """
    try:
        ctx = await authz.verify(auth, perm, host=request.headers.get("host"))
        role_permissions = set(ctx.role.permissions or [])
        if ctx.permissions:
            role_permissions.update(permission.id for permission in ctx.permissions)

        remote_headers: dict[str, str] = {
            "Remote-User": str(ctx.user.uuid),
            "Remote-Name": ctx.user.display_name,
            "Remote-Groups": ",".join(sorted(role_permissions)),
            "Remote-Org": str(ctx.org.uuid),
            "Remote-Org-Name": ctx.org.display_name,
            "Remote-Role": str(ctx.role.uuid),
            "Remote-Role-Name": ctx.role.display_name,
            "Remote-Session-Expires": (
                session_expiry(ctx.session)
                .astimezone(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
                if session_expiry(ctx.session).tzinfo
                else session_expiry(ctx.session)
                .replace(tzinfo=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            ),
            "Remote-Credential": str(ctx.session.credential_uuid),
        }
        return Response(status_code=204, headers=remote_headers)
    except HTTPException as e:
        # Let global handler clear cookie; still return HTML surface instead of JSON
        html = frontend.file("restricted", "index.html").read_bytes()
        status = e.status_code
        # If 401 we still want cookie cleared; rely on handler by raising again not feasible (we need HTML)
        if status == 401:
            session.clear_session_cookie(response)
        return Response(html, status_code=status, media_type="text/html")


@app.get("/settings")
async def get_settings():
    pk = global_passkey.instance
    base_path = hostutil.ui_base_path()
    return {
        "rp_id": pk.rp_id,
        "rp_name": pk.rp_name,
        "ui_base_path": base_path,
        "auth_host": hostutil.configured_auth_host(),
    }


@app.post("/user-info")
async def api_user_info(
    request: Request,
    response: Response,
    reset: str | None = None,
    auth=Cookie(None, alias="__Host-auth"),
):
    authenticated = False
    session_record = None
    reset_token = None
    try:
        if reset:
            if not passphrase.is_well_formed(reset):
                raise ValueError("Invalid reset token")
            reset_token = await get_reset(reset)
            target_user_uuid = reset_token.user_uuid
        else:
            if auth is None:
                raise ValueError("Authentication Required")
            session_record = await get_session(auth, host=request.headers.get("host"))
            authenticated = True
            target_user_uuid = session_record.user_uuid
    except ValueError as e:
        raise HTTPException(401, str(e))

    u = await db.instance.get_user_by_uuid(target_user_uuid)

    if not authenticated and reset_token:  # minimal response for reset tokens
        return {
            "authenticated": False,
            "session_type": reset_token.token_type,
            "user": {"user_uuid": str(u.uuid), "user_name": u.display_name},
        }

    assert auth is not None
    assert session_record is not None

    ctx = await permutil.session_context(auth, request.headers.get("host"))
    credential_ids = await db.instance.get_credentials_by_user_uuid(
        session_record.user_uuid
    )
    credentials: list[dict] = []
    user_aaguids: set[str] = set()
    for cred_id in credential_ids:
        try:
            c = await db.instance.get_credential_by_id(cred_id)
        except ValueError:
            continue
        aaguid_str = str(c.aaguid)
        user_aaguids.add(aaguid_str)
        credentials.append(
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
                "is_current_session": session_record.credential_uuid == c.uuid,
            }
        )
    credentials.sort(key=lambda cred: cred["created_at"])
    aaguid_info = aaguid.filter(user_aaguids)

    role_info = None
    org_info = None
    effective_permissions: list[str] = []
    is_global_admin = False
    is_org_admin = False
    if ctx:
        role_info = {
            "uuid": str(ctx.role.uuid),
            "display_name": ctx.role.display_name,
            "permissions": ctx.role.permissions,
        }
        org_info = {
            "uuid": str(ctx.org.uuid),
            "display_name": ctx.org.display_name,
            "permissions": ctx.org.permissions,
        }
        effective_permissions = [p.id for p in (ctx.permissions or [])]
        is_global_admin = "auth:admin" in (role_info["permissions"] or [])
        is_org_admin = any(
            p.startswith("auth:org:") for p in (role_info["permissions"] or [])
        )

    normalized_request_host = hostutil.normalize_host(request.headers.get("host"))
    session_records = await db.instance.list_sessions_for_user(session_record.user_uuid)
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
        "authenticated": True,
        "user": {
            "user_uuid": str(u.uuid),
            "user_name": u.display_name,
            "created_at": (
                u.created_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                if u.created_at and u.created_at.tzinfo
                else (
                    u.created_at.replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if u.created_at
                    else None
                )
            ),
            "last_seen": (
                u.last_seen.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
                if u.last_seen and u.last_seen.tzinfo
                else (
                    u.last_seen.replace(tzinfo=timezone.utc)
                    .isoformat()
                    .replace("+00:00", "Z")
                    if u.last_seen
                    else None
                )
            ),
            "visits": u.visits,
        },
        "org": org_info,
        "role": role_info,
        "permissions": effective_permissions,
        "is_global_admin": is_global_admin,
        "is_org_admin": is_org_admin,
        "credentials": credentials,
        "aaguid_info": aaguid_info,
        "sessions": sessions_payload,
    }


@app.put("/user/display-name")
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


@app.post("/logout")
async def api_logout(
    request: Request, response: Response, auth=Cookie(None, alias="__Host-auth")
):
    if not auth:
        return {"message": "Already logged out"}
    try:
        await get_session(auth, host=request.headers.get("host"))
    except ValueError:
        return {"message": "Already logged out"}
    with suppress(Exception):
        await db.instance.delete_session(session_key(auth))
    session.clear_session_cookie(response)
    return {"message": "Logged out successfully"}


@app.post("/user/logout-all")
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


@app.delete("/user/session/{session_id}")
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


@app.post("/set-session")
async def api_set_session(
    request: Request, response: Response, auth=Depends(bearer_auth)
):
    user = await get_session(auth.credentials, host=request.headers.get("host"))
    session.set_session_cookie(response, auth.credentials)
    return {
        "message": "Session cookie set successfully",
        "user_uuid": str(user.user_uuid),
    }


@app.delete("/user/credential/{uuid}")
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


@app.post("/user/create-link")
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
