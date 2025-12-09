from uuid import UUID

from fastapi import FastAPI, WebSocket

from paskia.authsession import create_session, get_reset, get_session
from paskia.fastapi import authz, remote
from paskia.fastapi.session import AUTH_COOKIE, infodict
from paskia.fastapi.wsutil import validate_origin, websocket_error_handler
from paskia.globals import db, passkey
from paskia.util import passphrase
from paskia.util.tokens import create_token, session_key

# Create a FastAPI subapp for WebSocket endpoints
app = FastAPI()

# Mount the remote auth WebSocket endpoints
app.mount("/remote-auth", remote.app)


async def register_chat(
    ws: WebSocket,
    user_uuid: UUID,
    user_name: str,
    origin: str,
    credential_ids: list[bytes] | None = None,
):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.instance.reg_generate_options(
        user_id=user_uuid,
        user_name=user_name,
        credential_ids=credential_ids,
    )
    await ws.send_json({"optionsJSON": options})
    response = await ws.receive_json()
    return passkey.instance.reg_verify(response, challenge, user_uuid, origin=origin)


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
        s = await get_reset(reset)
        user_uuid = s.user_uuid
    else:
        # Require recent authentication for adding a new passkey
        ctx = await authz.verify(auth, perm=[], host=host, max_age="5m")
        user_uuid = ctx.session.user_uuid
        s = ctx.session

    # Get user information and determine effective user_name for this registration
    user = await db.instance.get_user_by_uuid(user_uuid)
    user_name = user.display_name
    if name is not None:
        stripped = name.strip()
        if stripped:
            user_name = stripped
    challenge_ids = await db.instance.get_credentials_by_user_uuid(user_uuid)

    # WebAuthn registration
    credential = await register_chat(ws, user_uuid, user_name, origin, challenge_ids)

    # Create a new session and store everything in database
    token = create_token()
    metadata = infodict(ws, "authenticated")
    await db.instance.create_credential_session(  # type: ignore[attr-defined]
        user_uuid=user_uuid,
        credential=credential,
        reset_key=(s.key if reset is not None else None),
        session_key=session_key(token),
        display_name=user_name,
        host=host,
        ip=metadata.get("ip"),
        user_agent=metadata.get("user_agent"),
    )
    auth = token

    assert isinstance(auth, str) and len(auth) == 16
    await ws.send_json(
        {
            "user_uuid": str(user.uuid),
            "credential_uuid": str(credential.uuid),
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
        try:
            session = await get_session(auth, host=host)
            session_user_uuid = session.user_uuid
            credential_ids = await db.instance.get_credentials_by_user_uuid(
                session_user_uuid
            )
        except ValueError:
            pass  # Invalid/expired session - allow normal authentication

    options, challenge = passkey.instance.auth_generate_options(
        credential_ids=credential_ids
    )
    await ws.send_json({"optionsJSON": options})
    # Wait for the client to use his authenticator to authenticate
    credential = passkey.instance.auth_parse(await ws.receive_json())
    # Fetch from the database by credential ID
    try:
        stored_cred = await db.instance.get_credential_by_id(credential.raw_id)
    except ValueError:
        raise ValueError(
            f"This passkey is no longer registered with {passkey.instance.rp_name}"
        )

    # If reauth mode, verify the credential belongs to the session's user
    if session_user_uuid and stored_cred.user_uuid != session_user_uuid:
        raise ValueError("This passkey belongs to a different account")

    # Verify the credential matches the stored data
    passkey.instance.auth_verify(credential, challenge, stored_cred, origin)
    # Update both credential and user's last_seen timestamp
    await db.instance.login(stored_cred.user_uuid, stored_cred)

    # Create a session token for the authenticated user
    assert stored_cred.uuid is not None
    metadata = infodict(ws, "auth")
    token = await create_session(
        user_uuid=stored_cred.user_uuid,
        credential_uuid=stored_cred.uuid,
        host=host,
        ip=metadata.get("ip") or "",
        user_agent=metadata.get("user_agent") or "",
    )

    await ws.send_json(
        {
            "user_uuid": str(stored_cred.user_uuid),
            "session_token": token,
        }
    )
