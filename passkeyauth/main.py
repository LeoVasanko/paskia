"""
Minimal FastAPI WebAuthn server with WebSocket support for passkey registration and authentication.

This module provides a simple WebAuthn implementation that:
- Uses WebSocket for real-time communication
- Supports Resident Keys (discoverable credentials) for passwordless authentication
- Maintains challenges locally per connection
- Uses async SQLite database for persistent storage of users and credentials
- Enables true passwordless authentication where users don't need to enter a user_name
"""

from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import db
from .api_handlers import (
    delete_credential,
    get_user_credentials,
    get_user_info,
    logout,
    refresh_token,
    set_session,
    validate_token,
)
from .db import User
from .jwt_manager import create_session_token
from .passkey import Passkey
from .reset_handlers import create_device_addition_link, validate_device_addition_token
from .session_manager import get_user_from_cookie_string

STATIC_DIR = Path(__file__).parent.parent / "static"


passkey = Passkey(
    rp_id="localhost",
    rp_name="Passkey Auth",
    origin="http://localhost:8000",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_database()
    yield


app = FastAPI(title="Passkey Auth", lifespan=lifespan)


@app.websocket("/ws/new_user_registration")
async def websocket_register_new(ws: WebSocket):
    """Register a new user and with a new passkey credential."""
    await ws.accept()
    try:
        # Data for the new user account
        form = await ws.receive_json()
        user_id = uuid4()
        user_name = form["user_name"]

        # WebAuthn registration
        credential = await register_chat(ws, user_id, user_name)

        # Store the user and credential in the database
        await db.create_user_and_credential(
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


@app.websocket("/ws/add_credential")
async def websocket_register_add(ws: WebSocket):
    """Register a new credential for an existing user."""
    await ws.accept()
    try:
        # Authenticate user via cookie
        cookie_header = ws.headers.get("cookie", "")
        user_id = await get_user_from_cookie_string(cookie_header)

        if not user_id:
            await ws.send_json({"error": "Authentication required"})
            return

        # Get user information to get the user_name
        user = await db.get_user_by_id(user_id)
        user_name = user.user_name
        challenge_ids = await db.get_user_credentials(user_id)

        # WebAuthn registration
        credential = await register_chat(ws, user_id, user_name, challenge_ids)
        print(f"New credential for user {user_id}: {credential}")
        # Store the new credential in the database
        await db.create_credential_for_user(credential)

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
    except Exception as e:
        await ws.send_json({"error": f"Server error: {str(e)}"})


@app.websocket("/ws/add_device_credential")
async def websocket_add_device_credential(ws: WebSocket):
    """Add a new credential for an existing user via device addition token."""
    await ws.accept()
    try:
        # Get device addition token from client
        message = await ws.receive_json()
        token = message.get("token")

        if not token:
            await ws.send_json({"error": "Device addition token is required"})
            return

        # Validate device addition token
        reset_token = await db.get_reset_token(token)
        if not reset_token:
            await ws.send_json({"error": "Invalid or expired device addition token"})
            return

        # Check if token is expired (24 hours)
        from datetime import timedelta

        expiry_time = reset_token.created_at + timedelta(hours=24)
        if datetime.now() > expiry_time:
            await ws.send_json({"error": "Device addition token has expired"})
            return

        # Get user information
        user = await db.get_user_by_id(reset_token.user_id)
        challenge_ids = await db.get_user_credentials(reset_token.user_id)

        # WebAuthn registration
        credential = await register_chat(
            ws, reset_token.user_id, user.user_name, challenge_ids
        )

        # Store the new credential in the database
        await db.create_credential_for_user(credential)

        # Delete the device addition token (it's now used)
        await db.delete_reset_token(token)

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
    except Exception as e:
        await ws.send_json({"error": f"Server error: {str(e)}"})


async def register_chat(
    ws: WebSocket,
    user_id: UUID,
    user_name: str,
    credential_ids: list[bytes] | None = None,
):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.reg_generate_options(
        user_id=user_id,
        user_name=user_name,
        credential_ids=credential_ids,
    )
    await ws.send_json(options)
    response = await ws.receive_json()
    print(response)
    return passkey.reg_verify(response, challenge, user_id)


@app.websocket("/ws/authenticate")
async def websocket_authenticate(ws: WebSocket):
    await ws.accept()
    try:
        options, challenge = passkey.auth_generate_options()
        await ws.send_json(options)
        # Wait for the client to use his authenticator to authenticate
        credential = passkey.auth_parse(await ws.receive_json())
        # Fetch from the database by credential ID
        stored_cred = await db.get_credential_by_id(credential.raw_id)
        # Verify the credential matches the stored data
        passkey.auth_verify(credential, challenge, stored_cred)
        # Update both credential and user's last_seen timestamp
        await db.login_user(stored_cred.user_id, stored_cred)

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
    except ValueError as e:
        await ws.send_json({"error": str(e)})
    except WebSocketDisconnect:
        pass


@app.get("/api/user-info")
async def api_get_user_info(request: Request):
    """Get user information from session cookie."""
    return await get_user_info(request)


@app.get("/api/user-credentials")
async def api_get_user_credentials(request: Request):
    """Get all credentials for a user using session cookie."""
    return await get_user_credentials(request)


@app.post("/api/refresh-token")
async def api_refresh_token(request: Request, response: Response):
    """Refresh the session token."""
    return await refresh_token(request, response)


@app.get("/api/validate-token")
async def api_validate_token(request: Request):
    """Validate a session token and return user info."""
    return await validate_token(request)


@app.post("/api/logout")
async def api_logout(response: Response):
    """Log out the current user by clearing the session cookie."""
    return await logout(response)


@app.post("/api/set-session")
async def api_set_session(request: Request, response: Response):
    """Set session cookie using JWT token from request body or Authorization header."""
    return await set_session(request, response)


@app.post("/api/delete-credential")
async def api_delete_credential(request: Request):
    """Delete a specific credential for the current user."""
    return await delete_credential(request)


@app.post("/api/create-device-link")
async def api_create_device_link(request: Request):
    """Create a device addition link for the authenticated user."""
    return await create_device_addition_link(request)


@app.post("/api/validate-device-token")
async def api_validate_device_token(request: Request):
    """Validate a device addition token."""
    return await validate_device_addition_token(request)


# Serve static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def get_index():
    """Serve the main HTML page"""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/reset/{token}")
async def get_reset_page(token: str):
    """Serve the reset page with the token in URL"""
    return FileResponse(STATIC_DIR / "reset.html")


def main():
    """Entry point for the application"""
    import uvicorn

    uvicorn.run(
        "passkeyauth.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
