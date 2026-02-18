import secrets
from datetime import UTC, datetime
from urllib.parse import urlencode
from uuid import UUID

import base64url
from fastapi import FastAPI, WebSocket

from paskia import authcode, db
from paskia.authcode import CookieCode, OIDCCode
from paskia.authsession import get_reset
from paskia.db.structs import Session
from paskia.fastapi import authz, remote
from paskia.fastapi.session import AUTH_COOKIE, infodict
from paskia.fastapi.wschat import (
    authenticate_and_login,
    authenticate_chat,
    register_chat,
)
from paskia.fastapi.wsutil import validate_origin, websocket_error_handler
from paskia.globals import passkey
from paskia.util import hostutil, passphrase
from paskia.util.crypto import hash_secret


def create_exchange_code(session_key: str) -> str:
    """Create an ephemeral exchange code for session authentication."""
    now = datetime.now(UTC)
    cookie_code = CookieCode(
        session_key=session_key,
        created=now,
    )
    return authcode.store_cookie(cookie_code)


# Create a FastAPI subapp for WebSocket endpoints
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

# Mount the remote auth WebSocket endpoints
app.mount("/remote-auth", remote.app)


@app.websocket("/register")
@websocket_error_handler
async def websocket_register_add(
    ws: WebSocket,
    reset: str | None = None,
    name: str | None = None,
    auth=AUTH_COOKIE,
):
    """Register a new credential for an existing user.

    Supports either:
    - Normal session via auth cookie (requires recent authentication)
    - Reset token supplied as ?reset=... (auth cookie ignored)
    """
    origin = validate_origin(ws)
    host = hostutil.normalize_host(origin.split("://", 1)[1])
    if reset is not None:
        if not passphrase.is_well_formed(reset):
            raise ValueError(
                f"The reset link for {passkey.instance.rp_name} is invalid or has expired"
            )
        s = get_reset(reset)
        user_uuid = s.user_uuid
    else:
        # Require recent authentication for adding a new passkey
        ctx = await authz.verify(auth, perm=[], host=host, max_age="5m")
        user_uuid = ctx.session.user_uuid
        s = ctx.session

    # Get user information and determine effective user_name for this registration
    user = db.data().users[user_uuid]
    user_name = user.display_name
    if name is not None:
        stripped = name.strip()
        if stripped:
            user_name = stripped
    credential_ids = user.credential_ids or None

    # WebAuthn registration
    credential = await register_chat(ws, user_uuid, user_name, origin, credential_ids)

    # Create a new session and store everything in database
    metadata = infodict(ws, "authenticated")
    token = db.create_credential_session(
        user_uuid=user_uuid,
        credential=credential,
        reset_key=(s.key if reset is not None else None),
        display_name=user_name,
        host=host,
        ip=metadata["ip"],
        user_agent=metadata["user_agent"],
    )
    session_key = token

    # Create exchange code (ephemeral, 60s TTL)
    exchange_code = create_exchange_code(session_key)

    assert isinstance(session_key, str) and len(session_key) == 16
    await ws.send_json(
        {
            "user": str(user.uuid),
            "credential": str(credential.uuid),
            "exchange_code": exchange_code,
            "message": "New credential added successfully",
        }
    )


@app.websocket("/authenticate")
@websocket_error_handler
async def websocket_authenticate(
    ws: WebSocket,
    auth=AUTH_COOKIE,
    # OIDC params (when present, creates auth code instead of session)
    client_id: str | None = None,
    redirect_uri: str | None = None,
    scope: str = "openid",
    state: str | None = None,
    nonce: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
):
    origin = validate_origin(ws)
    host = origin.split("://", 1)[1]

    # OIDC mode: validate client before auth
    oidc_client = None
    if client_id and redirect_uri:
        try:
            client_uuid = UUID(client_id)
        except ValueError:
            await ws.send_json({"status": 400, "detail": "Invalid client_id"})
            return

        oidc_client = db.data().oidc.clients.get(client_uuid)
        if not oidc_client:
            await ws.send_json({"status": 400, "detail": "Unknown client_id"})
            return

        # Redirect URI autodiscovery: if no URIs are defined, store the first one
        if not oidc_client.redirect_uris:
            # Basic validation: must be an HTTP(S) URL
            if not redirect_uri.startswith(("http://", "https://")):
                await ws.send_json({"status": 400, "detail": "Invalid redirect_uri"})
                return
            # Store as the only allowed redirect URI
            db.update_oid_client(client_uuid, redirect_uris=[redirect_uri])
            # Reload client to get updated redirect_uris
            oidc_client = db.data().oidc.clients.get(client_uuid)
        elif redirect_uri not in oidc_client.redirect_uris:
            await ws.send_json({"status": 400, "detail": "Invalid redirect_uri"})
            return

        scopes = scope.split()
        if "openid" not in scopes:
            await ws.send_json({"status": 400, "detail": "Scope must include openid"})
            return

        # PKCE: when code_challenge is present, only S256 is supported
        # If method is omitted, default to S256 per best practice (not "plain" per RFC 7636)
        # When code_challenge is absent, ignore code_challenge_method entirely
        if code_challenge:
            if code_challenge_method and code_challenge_method != "S256":
                await ws.send_json(
                    {
                        "status": 400,
                        "detail": "Only S256 code_challenge_method is supported",
                    }
                )
                return
            # Default to S256 when method not specified (implicit)

        # Validate state parameter if provided (defensive against injection)
        if state:
            # State should be short-lived and contain only safe characters
            # Per OAuth 2.0 spec: unreserved characters - alphanumerics and -._~
            if len(state) > 500:
                await ws.send_json(
                    {
                        "status": 400,
                        "detail": "state parameter is too long (max 500 chars)",
                    }
                )
                return
            if not all(c.isalnum() or c in "-._~" for c in state):
                await ws.send_json(
                    {
                        "status": 400,
                        "detail": "state parameter contains invalid characters",
                    }
                )
                return

    # If there's an existing session, restrict to that user's credentials (reauth)
    session_user_uuid = None
    if auth:
        existing_ctx = db.data().session_ctx(auth, host)
        if existing_ctx:
            session_user_uuid = existing_ctx.user.uuid

    if oidc_client:
        # OIDC mode: authenticate and create OIDC session
        cred, new_sign_count = await authenticate_chat(ws)

        # Get metadata for session
        origin = validate_origin(ws)
        host = origin.split("://", 1)[1]
        normalized_host = hostutil.normalize_host(host)
        metadata = infodict(ws, "oidc_auth")

        # Use same timestamp for session and auth code
        now = datetime.now(UTC)

        # Generate token and create OIDC session
        token = secrets.token_urlsafe(12)
        session = Session.create(
            user=cred.user_uuid,
            credential=cred.uuid,
            key=base64url.enc(hash_secret("oidc", token)),
            host=normalized_host,
            ip=metadata["ip"],
            user_agent=metadata["user_agent"],
            validated=now,
            client=oidc_client.uuid,
        )
        db.oidc_login(
            session=session,
            credential_uuid=cred.uuid,
            sign_count=new_sign_count,
        )
        # Create auth code (in-memory only)
        oidc_code = OIDCCode(
            session_key=token,
            created=now,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            code_challenge=code_challenge,
        )
        code = authcode.store_oidc(oidc_code)

        # Build redirect URL
        params = {"code": code}
        if state:
            params["state"] = state
        redirect_url = f"{redirect_uri}?{urlencode(params)}"

        await ws.send_json({"redirect_url": redirect_url})
    else:
        # Normal mode: authenticate and create session
        ctx, session_key = await authenticate_and_login(ws, auth)

        # If reauth mode, verify the credential belongs to the session's user
        if session_user_uuid and ctx.user.uuid != session_user_uuid:
            raise ValueError("This passkey belongs to a different account")

        # Create exchange code (ephemeral, 60s TTL)
        exchange_code = create_exchange_code(session_key)

        await ws.send_json(
            {
                "user": str(ctx.user.uuid),
                "exchange_code": exchange_code,
            }
        )
