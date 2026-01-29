from fastapi import FastAPI, WebSocket

from paskia import db
from paskia.authsession import get_reset
from paskia.fastapi import authz, remote
from paskia.fastapi.session import AUTH_COOKIE, infodict
from paskia.fastapi.wschat import authenticate_and_login, register_chat
from paskia.fastapi.wsutil import validate_origin, websocket_error_handler
from paskia.globals import passkey
from paskia.util import passphrase

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
    host = origin.split("://", 1)[1]
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
    credential_ids = db.get_user_credential_ids(user_uuid) or None

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
    auth = token

    assert isinstance(auth, str) and len(auth) == 16
    await ws.send_json(
        {
            "user": str(user.uuid),
            "credential": str(credential.uuid),
            "session_token": auth,
            "message": "New credential added successfully",
        }
    )


@app.websocket("/authenticate")
@websocket_error_handler
async def websocket_authenticate(ws: WebSocket, auth=AUTH_COOKIE):
    origin = validate_origin(ws)
    host = origin.split("://", 1)[1]

    # If there's an existing session, restrict to that user's credentials (reauth)
    session_user_uuid = None
    credential_ids = None
    if auth:
        existing_ctx = db.data().session_ctx(auth, host)
        if existing_ctx:
            session_user_uuid = existing_ctx.user.uuid
            credential_ids = db.get_user_credential_ids(session_user_uuid) or None

    ctx = await authenticate_and_login(ws, credential_ids)

    # If reauth mode, verify the credential belongs to the session's user
    if session_user_uuid and ctx.user.uuid != session_user_uuid:
        raise ValueError("This passkey belongs to a different account")

    await ws.send_json(
        {
            "user": str(ctx.user.uuid),
            "session_token": ctx.session.key,
        }
    )
