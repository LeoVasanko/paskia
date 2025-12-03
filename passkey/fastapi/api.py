import logging
from contextlib import suppress
from datetime import datetime, timedelta, timezone

from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from passkey.util import frontend

from ..authsession import (
    EXPIRES,
    get_reset,
    get_session,
    refresh_session_token,
    session_expiry,
)
from ..globals import db
from ..globals import passkey as global_passkey
from ..util import hostutil, htmlutil, passphrase, userinfo
from ..util.tokens import session_key
from . import authz, session, user
from .session import AUTH_COOKIE

bearer_auth = HTTPBearer(auto_error=True)

app = FastAPI()

app.mount("/user", user.app)


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
    auth=AUTH_COOKIE,
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
        consumed = EXPIRES - (current_expiry - datetime.now(timezone.utc))
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
    max_age: str | None = Query(None),
    auth=AUTH_COOKIE,
):
    """Forward auth validation for Caddy/Nginx.

    Query Params:
    - perm: repeated permission IDs the authenticated user must possess (ALL required).
    - max_age: maximum age of authentication (e.g., "5m", "1h", "30s"). If the session
               is older than this, user must re-authenticate.

    Success: 204 No Content with Remote-* headers describing the authenticated user.
    Failure (unauthenticated / unauthorized): 4xx with HTML page for authentication.
             The HTML includes data attributes for mode and other metadata.
    """
    try:
        ctx = await authz.verify(
            auth, perm, host=request.headers.get("host"), max_age=max_age
        )
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
    except authz.AuthException as e:
        # Authentication/authorization failed - return HTML with metadata
        html = frontend.file("int", "forward", "index.html").read_bytes()
        # Inject mode and any additional metadata
        data_attrs = {"mode": e.mode, **e.metadata}
        html = htmlutil.patch_html_data_attrs(html, **data_attrs)
        # Clear cookie only if session is invalid (not for reauth)
        if e.clear_session:
            session.clear_session_cookie(response)
        return Response(
            html, status_code=e.status_code, media_type="text/html; charset=UTF-8"
        )


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
    auth=AUTH_COOKIE,
):
    """Get user information including credentials, sessions, and permissions.

    Can be called with either:
    - A session cookie (auth) for authenticated users
    - A reset token for users in password reset flow
    """
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

    # Return minimal response for reset tokens
    if not authenticated and reset_token:
        return await userinfo.format_reset_user_info(target_user_uuid, reset_token)

    # Return full user info for authenticated users
    assert auth is not None
    assert session_record is not None

    return await userinfo.format_user_info(
        user_uuid=target_user_uuid,
        auth=auth,
        session_record=session_record,
        request_host=request.headers.get("host"),
    )


@app.post("/logout")
async def api_logout(request: Request, response: Response, auth=AUTH_COOKIE):
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
