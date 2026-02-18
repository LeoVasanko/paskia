"""
OIDC Provider endpoints.

Implements OpenID Connect 1.0 Authorization Code flow:
- POST /token - Token endpoint (code exchange)
- GET /userinfo - UserInfo endpoint (bearer token)

Authorization is handled by /auth/restricted/oidc which passes OIDC params to
the /auth/ws/authenticate WebSocket.
"""

import base64
import hashlib
import logging
from datetime import UTC, datetime
from uuid import UUID

import base64url
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer

from paskia import authcode, db
from paskia.db.structs import Session
from paskia.util import oidjwt
from paskia.util.crypto import hash_secret

_logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/keys")
async def keys():
    """JSON Web Key Set for token verification."""
    return oidjwt.get_jwks()


def _oidc_session_by_token(
    token: str, client_uuid: UUID | None = None
) -> Session | None:
    """Look up an OIDC session by token (refresh token value)."""
    key = hash_secret("oidc", token)
    s = db.data().sessions.get(key)
    if not s or s.client_uuid is None:
        return None
    if client_uuid is not None and s.client_uuid != client_uuid:
        return None
    return s


def _oidc_session_by_sid(sid: bytes, client_uuid: UUID | None = None) -> Session | None:
    """Look up an OIDC session by sid (for backchannel logout)."""
    for s in db.data().sessions.values():
        if s.client_uuid is None:
            continue
        if client_uuid is not None and s.client_uuid != client_uuid:
            continue
        if base64url.dec(s.key) == sid:
            return s
    return None


def _get_issuer(request: Request) -> str:
    """Build issuer URL from request."""
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    return f"{scheme}://{host}"


def _verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify PKCE code_verifier against stored code_challenge (S256 only)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed == code_challenge


def _parse_client_credentials(
    request: Request,
    client_id: str | None,
    client_secret: str | None,
) -> tuple[str, str]:
    """Extract client credentials from request (Basic auth or body params)."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            raise HTTPException(401, "Invalid Authorization header")

    if not client_id or not client_secret:
        raise HTTPException(401, "Missing client credentials")

    return client_id, client_secret


@app.post("/token")
async def token(
    request: Request,
    grant_type: str = Form(...),
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    code_verifier: str | None = Form(None),
    refresh_token: str | None = Form(None),
):
    """OIDC Token endpoint.

    Supports:
    - grant_type=authorization_code: Exchange code for tokens
    - grant_type=refresh_token: Refresh access token using sid

    Supports client_secret_post and client_secret_basic authentication.
    Per RFC 6749 Section 4.1.3: MUST use POST with application/x-www-form-urlencoded.
    """

    # RFC 6749: Token endpoint MUST NOT accept query parameters
    if request.url.query:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "Query parameters not allowed",
            },
            status_code=400,
        )

    # RFC 6749: MUST use application/x-www-form-urlencoded
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in content_type:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "Content-Type must be application/x-www-form-urlencoded",
            },
            status_code=400,
        )

    # Get client credentials (required for all grant types)
    client_id, client_secret = _parse_client_credentials(
        request, client_id, client_secret
    )

    # Validate client
    try:
        client_uuid = UUID(client_id)
    except ValueError:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    client = db.data().oidc.clients.get(client_uuid)
    if not client or not client.verify_secret(client_secret):
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    if grant_type == "authorization_code":
        return await _handle_authorization_code(
            request, client, client_id, code, redirect_uri, code_verifier
        )
    elif grant_type == "refresh_token":
        return await _handle_refresh_token(request, client, client_id, refresh_token)
    else:
        return JSONResponse(
            {"error": "unsupported_grant_type"},
            status_code=400,
        )


async def _handle_authorization_code(
    request: Request,
    client,
    client_id: str,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
):
    """Handle grant_type=authorization_code."""
    if not code:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing code"},
            status_code=400,
        )

    # Consume auth code (atomic delete + return)
    oidc_code = authcode.consume_oidc(code)
    if not oidc_code:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "Code expired or invalid"},
            status_code=400,
        )

    # Look up the OIDC session by token
    session = _oidc_session_by_token(oidc_code.session_key, client.uuid)
    if not session:
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Session not found or not OIDC",
            },
            status_code=400,
        )

    # Verify redirect_uri matches
    if redirect_uri and redirect_uri != oidc_code.redirect_uri:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
            status_code=400,
        )

    # Verify PKCE if code_challenge was provided at authorization time
    if oidc_code.code_challenge:
        if not code_verifier:
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "Missing code_verifier",
                },
                status_code=400,
            )
        if not _verify_pkce(code_verifier, oidc_code.code_challenge):
            return JSONResponse(
                {
                    "error": "invalid_grant",
                    "error_description": "Invalid code_verifier",
                },
                status_code=400,
            )

    # Get user from session
    user = db.data().users.get(session.user_uuid)
    if not user:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "User not found"},
            status_code=400,
        )

    # Derive sid from session key
    sid = session.key

    return _build_token_response(
        request,
        user,
        client_id,
        oidc_code.session_key,
        sid,
        oidc_code.nonce,
        oidc_code.scope,
        credential_uuid=session.credential_uuid,
    )


async def _handle_refresh_token(
    request: Request,
    client,
    client_id: str,
    refresh_token_value: str | None,
):
    """Handle grant_type=refresh_token.

    The refresh_token is the session secret. On refresh:
    - Validates session exists and belongs to client
    - Extends session expiry (24h sliding window)
    - Records current IP and user_agent
    - Issues new access_token and id_token
    """
    if not refresh_token_value:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Missing refresh_token"},
            status_code=400,
        )

    # Look up session by refresh token
    session = _oidc_session_by_token(refresh_token_value, client.uuid)
    if not session:
        return JSONResponse(
            {
                "error": "invalid_grant",
                "error_description": "Invalid or expired refresh_token",
            },
            status_code=400,
        )

    # Get user
    user = db.data().users.get(session.user_uuid)
    if not user:
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "User not found"},
            status_code=400,
        )

    # Refresh the session - extend expiry and record IP/user_agent
    now = datetime.now(UTC)
    ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if request.client else ""
    user_agent = request.headers.get("user-agent", "")

    db.update_session(
        session.key,
        ip=ip,
        user_agent=user_agent,
        validated=now,
    )

    _logger.info("OIDC session refreshed: %s", session.key)

    # Base64url encode session's derived sid for JWT claim
    sid_str = session.key

    return _build_token_response(
        request,
        user,
        client_id,
        refresh_token_value,
        sid_str,
        nonce=None,
        scope="openid",
        credential_uuid=session.credential_uuid,
    )


def _build_token_response(
    request: Request,
    user,
    client_id: str,
    secret: str,
    sid: str,
    nonce: str | None,
    scope: str,
    credential_uuid: UUID | None = None,
):
    """Build the token response with access_token, id_token, and refresh_token."""
    issuer = _get_issuer(request)

    # Get user's permissions scoped to this OIDC client (domain == client UUID)
    role = user.role
    org = role.org
    org_perm_uuids = {p.uuid for p in org.permissions}
    groups = []
    for perm_uuid in role.permission_set:
        if perm_uuid not in org_perm_uuids:
            continue
        p = db.data().permissions.get(perm_uuid)
        if p and p.domain == client_id:
            groups.append(p.scope)

    # Get credential's last_used as auth_time
    auth_time = None
    if credential_uuid:
        try:
            credential = db.data().credentials[credential_uuid]
            if credential.last_used:
                auth_time = credential.last_used
        except KeyError:
            pass

    # Create ID token
    id_token = oidjwt.create_id_token(
        issuer=issuer,
        subject=user.uuid,
        audience=client_id,
        nonce=nonce,
        sid=sid,
        name=user.display_name,
        preferred_username=user.preferred_username,
        email=user.email,
        groups=groups or None,
        auth_time=auth_time,
    )

    # Create access token
    access_token = oidjwt.create_access_token(
        issuer=issuer,
        subject=user.uuid,
        audience=client_id,
        scope=scope,
    )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": secret,
            "id_token": id_token,
        }
    )


bearer_auth = HTTPBearer(auto_error=False)


@app.get("/userinfo")
async def userinfo(
    request: Request,
    credentials=Depends(bearer_auth),
):
    """OIDC UserInfo endpoint.

    Returns claims about the authenticated user.
    Requires Bearer token from /token endpoint.
    """
    if not credentials:
        raise HTTPException(401, "Bearer token required")

    issuer = _get_issuer(request)
    payload = oidjwt.decode_access_token(credentials.credentials, issuer)
    if not payload:
        raise HTTPException(401, "Invalid or expired token")

    # Verify audience is a valid client
    aud = payload.get("aud")
    if not aud:
        raise HTTPException(401, "Invalid token (missing aud claim)")

    try:
        client_uuid = UUID(aud)
    except ValueError:
        raise HTTPException(401, "Invalid token (invalid aud format)")

    if not db.data().oidc.clients.get(client_uuid):
        raise HTTPException(401, "Invalid token (unknown client)")

    # Get user
    try:
        user_uuid = UUID(payload["sub"])
    except (KeyError, ValueError):
        raise HTTPException(401, "Invalid token")

    user = db.data().users.get(user_uuid)
    if not user:
        raise HTTPException(401, "User not found")

    # Get user's permissions scoped to this OIDC client (domain == client UUID)
    role = user.role
    org = role.org
    org_perm_uuids = {p.uuid for p in org.permissions}
    groups = []
    for perm_uuid in role.permission_set:
        if perm_uuid not in org_perm_uuids:
            continue
        p = db.data().permissions.get(perm_uuid)
        if p and p.domain == aud:
            groups.append(p.scope)

    # Build userinfo response based on scope
    scope = payload.get("scope", "openid").split()
    response = {"sub": str(user.uuid)}

    if "profile" in scope:
        response["name"] = user.display_name
        if user.preferred_username:
            response["preferred_username"] = user.preferred_username

    if "email" in scope and user.email:
        response["email"] = user.email

    # Include client-scoped permissions as groups
    if groups:
        response["groups"] = groups

    return response


@app.post("/backchannel-logout")
async def backchannel_logout(
    request: Request,
    logout_token: str = Form(...),
):
    """OIDC Back-Channel Logout endpoint.

    Receives a logout_token JWT from the RP and invalidates the session.
    The logout_token must contain either 'sid' (session ID) or 'sub' (user ID).
    Per OIDC Back-Channel Logout 1.0: uses application/x-www-form-urlencoded.
    """
    # Validate content type
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" not in content_type:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "Content-Type must be application/x-www-form-urlencoded",
            },
            status_code=400,
        )

    # Decode and verify the logout token
    issuer = _get_issuer(request)
    payload = oidjwt.decode_access_token(logout_token, issuer)
    if not payload:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid logout_token"},
            status_code=400,
        )

    # Validate required claims
    sid = payload.get("sid")
    sub = payload.get("sub")

    # Verify audience is a valid client (if present)
    aud = payload.get("aud")
    client_uuid = None
    if aud:
        try:
            client_uuid = UUID(aud)
            if not db.data().oidc.clients.get(client_uuid):
                return JSONResponse(
                    {
                        "error": "invalid_request",
                        "error_description": "Unknown client in logout_token",
                    },
                    status_code=400,
                )
        except ValueError:
            return JSONResponse(
                {
                    "error": "invalid_request",
                    "error_description": "Invalid client format in logout_token",
                },
                status_code=400,
            )

    if not sid and not sub:
        return JSONResponse(
            {
                "error": "invalid_request",
                "error_description": "logout_token must contain sid or sub",
            },
            status_code=400,
        )

    # Delete session(s)
    deleted = 0
    if sid:
        # Decode sid from base64url to bytes
        try:
            sid_bytes = base64url.dec(sid)
        except Exception:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid sid format"},
                status_code=400,
            )
        # Delete specific session by sid
        session = _oidc_session_by_sid(sid_bytes, client_uuid)
        if session:
            db.delete_session(session.key)
            deleted = 1
            _logger.info("Back-channel logout: deleted session %s", sid)
    elif sub:
        # Delete all OIDC sessions for this user/client
        try:
            user_uuid = UUID(sub)
        except ValueError:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid sub claim"},
                status_code=400,
            )
        # Find and delete matching sessions
        sessions_to_delete = [
            s
            for s in db.data().sessions.values()
            if s.user_uuid == user_uuid
            and s.client_uuid is not None
            and (client_uuid is None or s.client_uuid == client_uuid)
        ]
        for session in sessions_to_delete:
            db.delete_session(session.key)
            deleted += 1
        if deleted:
            _logger.info(
                "Back-channel logout: deleted %d sessions for user %s", deleted, sub
            )

    # Return 200 OK even if no sessions were found (per spec)
    return JSONResponse({"deleted": deleted})
