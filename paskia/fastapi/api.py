import logging
from contextlib import suppress
from datetime import UTC, datetime, timedelta

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

from paskia import db
from paskia.authsession import EXPIRES, expires, get_reset
from paskia.fastapi import authz, session, user
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE, AUTH_COOKIE_NAME
from paskia.globals import passkey as global_passkey
from paskia.util import hostutil, htmlutil, passphrase, userinfo, vitedev

bearer_auth = HTTPBearer(auto_error=True)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

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


@app.exception_handler(authz.AuthException)
async def auth_exception_handler(_request: Request, exc: authz.AuthException):
    """Handle AuthException with auth info for UI."""
    return JSONResponse(
        status_code=exc.status_code,
        content=await authz.auth_error_content(exc),
    )


@app.exception_handler(Exception)
async def general_exception_handler(
    _request: Request, exc: Exception
):  # pragma: no cover
    logging.exception("Unhandled exception in API app")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.post("/validate")
async def validate_token(
    request: Request,
    response: Response,
    perm: list[str] = Query([]),
    max_age: str | None = Query(None),
    auth=AUTH_COOKIE,
):
    """Validate session and return context. Refreshes session expiry."""
    try:
        ctx = await authz.verify(
            auth,
            " ".join(perm).split(),
            host=request.headers.get("host"),
            max_age=max_age,
        )
    except HTTPException:
        # Global handler will clear cookie if 401
        raise
    renewed = False
    if auth:
        consumed = EXPIRES - (ctx.session.expiry - datetime.now(UTC))
        if not timedelta(0) < consumed < _REFRESH_INTERVAL:
            db.update_session(
                auth,
                ip=request.client.host if request.client else "",
                user_agent=request.headers.get("user-agent") or "",
                expiry=expires(),
                ctx=ctx,
            )
            session.set_session_cookie(response, auth)
            renewed = True
    return MsgspecResponse(
        {
            "valid": True,
            "renewed": renewed,
            "ctx": userinfo.build_session_context(ctx),
        }
    )


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
    Failure (unauthenticated / unauthorized): 4xx response.
        - If Accept header contains "text/html": HTML page for authentication
          with data attributes for mode and other metadata.
        - Otherwise: JSON response with error details and an `iframe` field
          pointing to /auth/restricted/?mode=... for iframe-based authentication.
    """
    try:
        ctx = await authz.verify(
            auth,
            " ".join(perm).split(),
            host=request.headers.get("host"),
            max_age=max_age,
        )
        # Build permission scopes for Remote-Groups header
        role_permissions = (
            {p.scope for p in ctx.permissions} if ctx.permissions else set()
        )

        remote_headers: dict[str, str] = {
            "Remote-User": str(ctx.user.uuid),
            "Remote-Name": ctx.user.display_name,
            "Remote-Groups": ",".join(sorted(role_permissions)),
            "Remote-Org": str(ctx.org.uuid),
            "Remote-Org-Name": ctx.org.display_name,
            "Remote-Role": str(ctx.role.uuid),
            "Remote-Role-Name": ctx.role.display_name,
            "Remote-Session-Expires": (
                ctx.session.expiry.astimezone(UTC).isoformat().replace("+00:00", "Z")
                if ctx.session.expiry.tzinfo
                else ctx.session.expiry.replace(tzinfo=UTC)
                .isoformat()
                .replace("+00:00", "Z")
            ),
            "Remote-Credential": str(ctx.session.credential),
        }
        return Response(status_code=204, headers=remote_headers)
    except authz.AuthException as e:
        # Clear cookie only if session is invalid (not for reauth)
        if e.clear_session:
            session.clear_session_cookie(response)

        # Check Accept header to decide response format
        accept = request.headers.get("accept", "")
        wants_html = "text/html" in accept

        if wants_html:
            # Browser request - return full-page HTML with metadata
            data_attrs = {"mode": e.mode, **e.metadata}
            html = (await vitedev.read("/int/forward/index.html"))[0]
            html = htmlutil.patch_html_data_attrs(html, **data_attrs)
            return Response(
                html, status_code=e.status_code, media_type="text/html; charset=UTF-8"
            )
        else:
            # API request - return JSON with iframe srcdoc HTML
            return JSONResponse(
                status_code=e.status_code,
                content=await authz.auth_error_content(e),
            )


@app.get("/settings")
async def get_settings():
    pk = global_passkey.instance
    base_path = hostutil.ui_base_path()
    return {
        "rp_id": pk.rp_id,
        "rp_name": pk.rp_name,
        "ui_base_path": base_path,
        "auth_host": hostutil.dedicated_auth_host(),
        "auth_site_url": hostutil.auth_site_url(),
        "session_cookie": AUTH_COOKIE_NAME,
    }


@app.post("/user-info")
async def api_user_info(
    request: Request,
    response: Response,
    auth=AUTH_COOKIE,
):
    """Get full user profile including credentials and sessions."""
    if auth is None:
        raise authz.AuthException(
            status_code=401,
            detail="Authentication required",
            mode="login",
        )
    ctx = db.data().session_ctx(auth, request.headers.get("host"))
    if not ctx:
        raise HTTPException(401, "Session expired")

    return MsgspecResponse(
        await userinfo.build_user_info(
            user_uuid=ctx.user.uuid,
            auth=auth,
            session_record=ctx.session,
            request_host=request.headers.get("host"),
        )
    )


@app.get("/token-info")
async def token_info(credentials=Depends(bearer_auth)):
    """Get reset/device-add token info. Pass token via Bearer header."""
    token = credentials.credentials
    if not passphrase.is_well_formed(token):
        raise HTTPException(400, "Invalid token format")
    try:
        reset_token = get_reset(token)
    except ValueError as e:
        raise HTTPException(401, str(e))

    u = reset_token.user
    return {
        "token_type": reset_token.token_type,
        "display_name": u.display_name,
    }


@app.post("/logout")
async def api_logout(request: Request, response: Response, auth=AUTH_COOKIE):
    if not auth:
        return {"message": "Already logged out"}
    host = request.headers.get("host")
    ctx = db.data().session_ctx(auth, host)
    if not ctx:
        return {"message": "Already logged out"}
    with suppress(Exception):
        db.delete_session(auth, ctx=ctx, action="logout")
    session.clear_session_cookie(response)
    return {"message": "Logged out successfully"}


@app.post("/set-session")
async def api_set_session(
    request: Request, response: Response, auth=Depends(bearer_auth)
):
    ctx = db.data().session_ctx(auth.credentials, request.headers.get("host"))
    if not ctx:
        raise HTTPException(401, "Session expired")
    session.set_session_cookie(response, auth.credentials)
    return {
        "message": "Session cookie set successfully",
        "user": str(ctx.user.uuid),
    }
