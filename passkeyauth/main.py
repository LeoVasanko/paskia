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
from uuid import UUID

import uuid7
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import Credential, User, db
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
        form = await ws.receive_json()
        now = datetime.now()
        user_id = uuid7.create(now).bytes
        user_name = form["user_name"]

        # Generate registration options and handle registration
        credential, verified = await register_chat(ws, user_id, user_name)

        # Store the user in the database
        await db.create_user(User(user_id, user_name, now))
        await db.store_credential(
            Credential(
                credential_id=credential.raw_id,
                user_id=user_id,
                aaguid=UUID(verified.aaguid),
                public_key=verified.credential_public_key,
                sign_count=verified.sign_count,
                created_at=now,
            )
        )
        await ws.send_json({"status": "success", "user_id": user_id.hex()})
    except WebSocketDisconnect:
        pass


async def register_chat(ws: WebSocket, user_id: bytes, user_name: str):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.reg_generate_options(
        user_id=user_id,
        user_name=user_name,
    )
    await ws.send_json(options)
    # Wait for the client to use his authenticator to register
    credential = passkey.reg_credential(await ws.receive_json())
    verified_registration = passkey.reg_verify(credential, challenge)
    return credential, verified_registration


@app.websocket("/ws/authenticate")
async def websocket_authenticate(ws: WebSocket):
    await ws.accept()
    try:
        options, challenge = await passkey.auth_generate_options()
        await ws.send_json(options)
        # Wait for the client to use his authenticator to authenticate
        credential = passkey.auth_credential(await ws.receive_json())
        # Fetch from the database by credential ID
        stored_cred = await db.get_credential_by_id(credential.raw_id)
        # Verify the credential matches the stored data
        _ = await passkey.auth_verify(credential, challenge, stored_cred)
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
