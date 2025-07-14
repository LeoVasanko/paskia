"""
WebSocket handlers for passkey authentication operations.

This module contains all WebSocket endpoints for:
- User registration
- Adding credentials to existing users
- Device credential addition via token
- Authentication
"""

import logging
from datetime import datetime, timedelta
from uuid import UUID

import uuid7
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from ..db import sql
from ..db.sql import User
from ..sansio import Passkey
from ..util.jwt import create_session_token
from .session_manager import get_user_from_cookie_string

# Create a FastAPI subapp for WebSocket endpoints
ws_app = FastAPI()

# Initialize the passkey instance
passkey = Passkey(
    rp_id="localhost",
    rp_name="Passkey Auth",
)


async def register_chat(
    ws: WebSocket,
    user_id: UUID,
    user_name: str,
    credential_ids: list[bytes] | None = None,
    origin: str | None = None,
):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.reg_generate_options(
        user_id=user_id,
        user_name=user_name,
        credential_ids=credential_ids,
        origin=origin,
    )
    await ws.send_json(options)
    response = await ws.receive_json()
    return passkey.reg_verify(response, challenge, user_id, origin=origin)


@ws_app.websocket("/register_new")
async def websocket_register_new(ws: WebSocket, user_name: str):
    """Register a new user and with a new passkey credential."""
    await ws.accept()
    origin = ws.headers.get("origin")
    try:
        user_id = uuid7.create()

        # WebAuthn registration
        credential = await register_chat(ws, user_id, user_name, origin=origin)

        # Store the user and credential in the database
        await sql.create_user_and_credential(
            User(user_id, user_name, created_at=datetime.now()),
            credential,
        )

        # Create a session token for the new user
        session_token = create_session_token(user_id, credential.credential_id)

        await ws.send_json(
            {
                "status": "success",
                "user_id": str(user_id),
                "session_token": session_token,
            }
        )
    except ValueError as e:
        await ws.send_json({"error": str(e)})
    except WebSocketDisconnect:
        pass
    except Exception:
        logging.exception("Internal Server Error")
        await ws.send_json({"error": "Internal Server Error"})


@ws_app.websocket("/add_credential")
async def websocket_register_add(ws: WebSocket):
    """Register a new credential for an existing user."""
    await ws.accept()
    origin = ws.headers.get("origin")
    try:
        # Authenticate user via cookie
        cookie_header = ws.headers.get("cookie", "")
        user_id = await get_user_from_cookie_string(cookie_header)

        if not user_id:
            await ws.send_json({"error": "Authentication required"})
            return

        # Get user information to get the user_name
        user = await sql.get_user_by_id(user_id)
        user_name = user.user_name
        challenge_ids = await sql.get_user_credentials(user_id)

        # WebAuthn registration
        credential = await register_chat(
            ws, user_id, user_name, challenge_ids, origin=origin
        )
        # Store the new credential in the database
        await sql.create_credential_for_user(credential)

        await ws.send_json(
            {
                "status": "success",
                "user_id": str(user_id),
                "credential_id": credential.credential_id.hex(),
                "message": "New credential added successfully",
            }
        )
    except ValueError as e:
        await ws.send_json({"error": str(e)})
    except WebSocketDisconnect:
        pass
    except Exception:
        logging.exception("Internal Server Error")
        await ws.send_json({"error": "Internal Server Error"})


@ws_app.websocket("/add_device_credential")
async def websocket_add_device_credential(ws: WebSocket, token: str):
    """Add a new credential for an existing user via device addition token."""
    await ws.accept()
    origin = ws.headers.get("origin")
    try:
        reset_token = await sql.get_reset_token(token)
        if not reset_token:
            await ws.send_json({"error": "Invalid or expired device addition token"})
            return

        # Check if token is expired (24 hours)
        expiry_time = reset_token.created_at + timedelta(hours=24)
        if datetime.now() > expiry_time:
            await ws.send_json({"error": "Device addition token has expired"})
            return

        # Get user information
        user = await sql.get_user_by_id(reset_token.user_id)

        # WebAuthn registration
        # Fetch challenge IDs for the user
        challenge_ids = await sql.get_user_credentials(reset_token.user_id)

        credential = await register_chat(
            ws, reset_token.user_id, user.user_name, challenge_ids, origin=origin
        )

        # Store the new credential in the database
        await sql.create_credential_for_user(credential)

        # Delete the device addition token (it's now used)
        await sql.delete_reset_token(token)

        await ws.send_json(
            {
                "status": "success",
                "user_id": str(reset_token.user_id),
                "credential_id": credential.credential_id.hex(),
                "message": "New credential added successfully via device addition token",
            }
        )
    except ValueError as e:
        await ws.send_json({"error": str(e)})
    except WebSocketDisconnect:
        pass
    except Exception:
        logging.exception("Internal Server Error")
        await ws.send_json({"error": "Internal Server Error"})


@ws_app.websocket("/authenticate")
async def websocket_authenticate(ws: WebSocket):
    await ws.accept()
    origin = ws.headers.get("origin")
    try:
        options, challenge = passkey.auth_generate_options()
        await ws.send_json(options)
        # Wait for the client to use his authenticator to authenticate
        credential = passkey.auth_parse(await ws.receive_json())
        # Fetch from the database by credential ID
        stored_cred = await sql.get_credential_by_id(credential.raw_id)
        # Verify the credential matches the stored data
        passkey.auth_verify(credential, challenge, stored_cred, origin=origin)
        # Update both credential and user's last_seen timestamp
        await sql.login_user(stored_cred.user_id, stored_cred)

        # Create a session token for the authenticated user
        session_token = create_session_token(
            stored_cred.user_id, stored_cred.credential_id
        )

        await ws.send_json(
            {
                "status": "success",
                "user_id": str(stored_cred.user_id),
                "session_token": session_token,
            }
        )
    except (ValueError, InvalidAuthenticationResponse) as e:
        logging.exception("ValueError")
        await ws.send_json({"error": str(e)})
    except WebSocketDisconnect:
        pass
    except Exception:
        logging.exception("Internal Server Error")
        await ws.send_json({"error": "Internal Server Error"})
