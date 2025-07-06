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
from pathlib import Path
from uuid import UUID

import uuid7
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import User, db
from .passkey import Passkey

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
        user_id = uuid7.create()
        user_name = form["user_name"]

        # WebAuthn registration
        credential = await register_chat(ws, user_id, user_name)

        credential.created_at = now
        # Store the user in the database
        await db.create_user(User(user_id, user_name, now))
        await db.store_credential(credential)
        await ws.send_json({"status": "success", "user_id": user_id.hex()})
    except WebSocketDisconnect:
        pass


async def register_chat(ws: WebSocket, user_id: UUID, user_name: str):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.reg_generate_options(
        user_id=user_id,
        user_name=user_name,
    )
    await ws.send_json(options)
    response = await ws.receive_json()
    return passkey.reg_verify(response, challenge, user_id)


@app.websocket("/ws/authenticate")
async def websocket_authenticate(ws: WebSocket):
    await ws.accept()
    try:
        options, challenge = await passkey.auth_generate_options()
        await ws.send_json(options)
        # Wait for the client to use his authenticator to authenticate
        credential = passkey.auth_parse(await ws.receive_json())
        # Fetch from the database by credential ID
        stored_cred = await db.get_credential_by_id(credential.raw_id)
        # Verify the credential matches the stored data
        await passkey.auth_verify(credential, challenge, stored_cred)
        await db.update_credential(stored_cred)
        await ws.send_json({"status": "success"})
    except WebSocketDisconnect:
        pass


# Serve static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def get_index():
    """Serve the main HTML page"""
    return FileResponse(STATIC_DIR / "index.html")


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
