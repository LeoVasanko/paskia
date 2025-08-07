import logging
from datetime import datetime
from functools import wraps
from uuid import UUID

import uuid7
from fastapi import Cookie, FastAPI, Query, WebSocket, WebSocketDisconnect
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from ..authsession import EXPIRES, create_session, get_reset, get_session
from ..db import User
from ..globals import db, passkey
from ..util import passphrase
from ..util.tokens import create_token, session_key
from .session import infodict


# WebSocket error handling decorator
def websocket_error_handler(func):
    @wraps(func)
    async def wrapper(ws: WebSocket, *args, **kwargs):
        try:
            await ws.accept()
            return await func(ws, *args, **kwargs)
        except WebSocketDisconnect:
            pass
        except (ValueError, InvalidAuthenticationResponse) as e:
            await ws.send_json({"detail": str(e)})
        except Exception:
            logging.exception("Internal Server Error")
            await ws.send_json({"detail": "Internal Server Error"})

    return wrapper


# Create a FastAPI subapp for WebSocket endpoints
app = FastAPI()


async def register_chat(
    ws: WebSocket,
    user_uuid: UUID,
    user_name: str,
    credential_ids: list[bytes] | None = None,
    origin: str | None = None,
):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.instance.reg_generate_options(
        user_id=user_uuid,
        user_name=user_name,
        credential_ids=credential_ids,
        origin=origin,
    )
    await ws.send_json(options)
    response = await ws.receive_json()
    return passkey.instance.reg_verify(response, challenge, user_uuid, origin=origin)


@app.websocket("/register")
@websocket_error_handler
async def websocket_register_new(
    ws: WebSocket, user_name: str = Query(""), auth=Cookie(None)
):
    """Register a new user and with a new passkey credential."""
    origin = ws.headers["origin"]
    user_uuid = uuid7.create()
    # WebAuthn registration
    credential = await register_chat(ws, user_uuid, user_name, origin=origin)

    # Store the user and credential in the database
    await db.instance.create_user_and_credential(
        User(user_uuid, user_name, created_at=datetime.now()),
        credential,
    )
    # Create a session token for the new user
    token = create_token()
    await db.instance.create_session(
        user_uuid=user_uuid,
        key=session_key(token),
        expires=datetime.now() + EXPIRES,
        info=infodict(ws, "authenticated"),
        credential_uuid=credential.uuid,
    )

    await ws.send_json(
        {
            "user_uuid": str(user_uuid),
            "session_token": token,
        }
    )


@app.websocket("/add_credential")
@websocket_error_handler
async def websocket_register_add(ws: WebSocket, auth=Cookie(None)):
    """Register a new credential for an existing user."""
    origin = ws.headers["origin"]
    # Try to get either a regular session or a reset session
    reset = passphrase.is_well_formed(auth)
    s = await (get_reset if reset else get_session)(auth)
    user_uuid = s.user_uuid

    # Get user information to get the user_name
    user = await db.instance.get_user_by_uuid(user_uuid)
    user_name = user.display_name
    challenge_ids = await db.instance.get_credentials_by_user_uuid(user_uuid)

    # WebAuthn registration
    credential = await register_chat(ws, user_uuid, user_name, challenge_ids, origin)
    if reset:
        # Replace reset session with a new session
        await db.instance.delete_session(s.key)
        token = await create_session(
            user_uuid, credential.uuid, infodict(ws, "authenticated")
        )
    else:
        token = auth
    assert isinstance(token, str) and len(token) == 16
    # Store the new credential in the database
    await db.instance.create_credential(credential)

    await ws.send_json(
        {
            "user_uuid": str(user.uuid),
            "credential_uuid": str(credential.uuid),
            "session_token": token,
            "message": "New credential added successfully",
        }
    )


@app.websocket("/authenticate")
@websocket_error_handler
async def websocket_authenticate(ws: WebSocket):
    origin = ws.headers["origin"]
    options, challenge = passkey.instance.auth_generate_options()
    await ws.send_json(options)
    # Wait for the client to use his authenticator to authenticate
    credential = passkey.instance.auth_parse(await ws.receive_json())
    # Fetch from the database by credential ID
    stored_cred = await db.instance.get_credential_by_id(credential.raw_id)
    # Verify the credential matches the stored data
    passkey.instance.auth_verify(credential, challenge, stored_cred, origin=origin)
    # Update both credential and user's last_seen timestamp
    await db.instance.login(stored_cred.user_uuid, stored_cred)

    # Create a session token for the authenticated user
    assert stored_cred.uuid is not None
    token = await create_session(
        user_uuid=stored_cred.user_uuid,
        info=infodict(ws, "auth"),
        credential_uuid=stored_cred.uuid,
    )

    await ws.send_json(
        {
            "user_uuid": str(stored_cred.user_uuid),
            "session_token": token,
        }
    )
