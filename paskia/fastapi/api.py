import logging
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from uuid import UUID

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

from paskia import authcode, db
from paskia._version import __version__
from paskia.authsession import EXPIRES, get_reset, session_ctx
from paskia.fastapi import authz, session, user
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE, AUTH_COOKIE_NAME, get_client_ip
from paskia.globals import passkey as global_passkey
from paskia.util.crypto import hash_secret
from paskia.util import hostutil, htmlutil, passphrase, permutil, userinfo
from paskia.util.apistructs import (
    ApiCheckUserResponse,
    ApiOrgContext,
    ApiRoleContext,
    ApiSessionContext,
    ApiSettings,
    ApiTokenInfo,
    ApiUserContext,
    ApiValidateResponse,
)

bearer_auth = HTTPBearer(auto_error=False)

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


def _set_log_extra(request: Request, *parts: str) -> None:
    values = [part for part in parts if part]
    if values:
        request.state.log_extra = " ".join(values)


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
        consumed = datetime.now(UTC) - ctx.session.validated
        if not timedelta(0) < consumed < _REFRESH_INTERVAL:
            db.update_session(
                ctx.session.key,
                ip=get_client_ip(request),
                user_agent=request.headers.get("user-agent") or "",
                validated=datetime.now(UTC),
                ctx=ctx,
            )
            session.set_session_cookie(response, auth)
            renewed = True
        _set_log_extra(request, ctx.session.key)
    return MsgspecResponse(
        ApiValidateResponse(
            valid=True,
            renewed=renewed,
            ctx=userinfo.build_session_context(ctx),
        )
    )


@app.get("/check")
async def check_user(
    request: Request,
    user_uuid: UUID = Query(..., alias="user"),
    perm: list[str] = Query([]),
):
    """Check permissions for a user by UUID without requiring a session.

    Query Params:
    - user: UUID of the user to check.
    - perm: repeated permission scope the user must possess (ALL required).

    Returns 200 with valid=True/False and the user's effective permissions,
    scoped to the requesting host (domain-restricted permissions are filtered).
    Returns 404 if the user UUID does not exist.

    No session cookie is read or written. Caller authentication is not required.
    """
    data = db.data()
    try:
        u = data.users[user_uuid]
        role = u.role
        org = role.org
    except KeyError:
        raise HTTPException(status_code=404, detail="User not found")

    host = hostutil.normalize_host(request.headers.get("host"))
    org_perm_uuids = {p.uuid for p in org.permissions}

    effective_perms = []
    for perm_uuid in role.permission_set:
        if perm_uuid not in org_perm_uuids:
            continue
        try:
            p = data.permissions[perm_uuid]
        except KeyError:
            continue
        if p.domain is not None and p.domain != host:
            continue
        effective_perms.append(p)

    required = " ".join(perm).split()
    effective_scopes = {p.scope for p in effective_perms}
    valid = permutil.has_all_scopes(effective_scopes, required)

    ctx = ApiSessionContext(
        user=ApiUserContext(uuid=u.uuid, display_name=u.display_name, theme=u.theme),
        org=ApiOrgContext(uuid=org.uuid, display_name=org.display_name),
        role=ApiRoleContext(uuid=role.uuid, display_name=role.display_name),
        permissions=sorted(effective_scopes),
    )
    return MsgspecResponse(ApiCheckUserResponse(valid=valid, ctx=ctx))


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
          pointing to /auth/restricted/iframe#mode=... for iframe-based authentication.
    """
    forwarded_method = request.headers.get("x-forwarded-method", "").strip()
    forwarded_uri = request.headers.get("x-forwarded-uri", "").strip()
    forwarded = (
        f"{forwarded_method} {forwarded_uri}"
        if forwarded_method and forwarded_uri
        else ""
    )
    _set_log_extra(request, forwarded)

    try:
        ctx = await authz.verify(
            auth,
            " ".join(perm).split(),
            host=request.headers.get("host"),
            max_age=max_age,
        )
        _set_log_extra(request, forwarded, ctx.session.key)
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
                (ctx.session.validated + EXPIRES).isoformat().replace("+00:00", "Z")
            ),
            "Remote-Credential": str(ctx.session.credential),
        }
        return Response(status_code=204, headers=remote_headers)
    except authz.AuthException as e:
        # Clear cookie only if session is invalid (not for reauth)
        if e.clear_session:
            session.clear_session_cookie(response)
        # Browser request? - return full-page HTML with metadata patched into data attrs
        if "text/html" in request.headers.get("accept", ""):
            return await htmlutil.patched_html_response(
                request, "/int/forward/", e.status_code, mode=e.mode, **e.metadata
            )
        # API request - return JSON with iframe srcdoc HTML
        return JSONResponse(
            status_code=e.status_code, content=await authz.auth_error_content(e)
        )


@app.get("/settings")
async def get_settings():
    pk = global_passkey.instance
    base_path = hostutil.ui_base_path()
    return MsgspecResponse(
        ApiSettings(
            rp_id=pk.rp_id,
            rp_name=pk.rp_name,
            ui_base_path=base_path,
            auth_host=hostutil.dedicated_auth_host(),
            auth_site_url=hostutil.auth_site_url(),
            session_cookie=AUTH_COOKIE_NAME,
            version=__version__,
        ),
        headers={"Access-Control-Allow-Origin": "*", "Vary": "Origin"},
    )


@app.get("/user-info")
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
    ctx = session_ctx(auth, request.headers.get("host"))
    if not ctx:
        raise authz.AuthException(
            status_code=401,
            detail="Session expired",
            mode="login",
            clear_session=True,
        )

    _set_log_extra(request, ctx.session.key)

    return MsgspecResponse(
        await userinfo.build_user_info(
            user_uuid=ctx.user.uuid,
            session_key=ctx.session.key,
            request_host=request.headers.get("host"),
            ctx=ctx,
        )
    )


@app.get("/token-info")
async def token_info(credentials=Depends(bearer_auth)):
    """Get reset/device-add token info. Pass token via Bearer header."""
    if not credentials or not credentials.credentials:
        raise HTTPException(401, "Bearer token required")
    token = credentials.credentials
    if not passphrase.is_well_formed(token):
        raise HTTPException(400, "Invalid token format")
    try:
        reset_token = get_reset(token)
    except ValueError as e:
        raise HTTPException(401, str(e))

    u = reset_token.user
    return MsgspecResponse(
        ApiTokenInfo(
            token_type=reset_token.token_type,
            display_name=u.display_name,
            theme=u.theme,
        )
    )


@app.post("/logout")
async def api_logout(request: Request, response: Response, auth=AUTH_COOKIE):
    if not auth:
        return {"message": "Already logged out"}
    host = request.headers.get("host")
    ctx = session_ctx(auth, host)
    if not ctx:
        return {"message": "Already logged out"}
    with suppress(Exception):
        db.delete_session(ctx.session.key, ctx=ctx, action="logout")
    session.clear_session_cookie(response)
    return {"message": "Logged out successfully"}


@app.post("/set-session")
async def api_set_session(
    request: Request, response: Response, auth=Depends(bearer_auth)
):
    """Exchange an auth code for setting the session cookie.

    Called by frontend after WebSocket authentication.
    The code is ephemeral (60s TTL) and can only be used once.
    """
    if not auth or not auth.credentials:
        raise HTTPException(400, "Bearer token required")

    # Verify host is provided
    host = hostutil.normalize_host(request.headers.get("host", ""))
    if not host:
        raise HTTPException(400, "Host header required")

    a = authcode.consume_cookie(auth.credentials)
    if not a:
        raise HTTPException(401, "Code expired or already used")

    secret = a.session_key

    # Verify the session exists
    ctx = session_ctx(secret, host)
    if not ctx:
        raise HTTPException(401, f"Session not found on {host}")

    _set_log_extra(request, hash_secret("cookie", secret))
    session.set_session_cookie(response, secret)
    return {"status": "ok", "user": str(ctx.user.uuid)}
