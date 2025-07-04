"""
Minimal FastAPI WebAuthn server with WebSocket support for passkey registration and authentication.

This module provides a simple WebAuthn implementation that:
- Uses WebSocket for real-time communication
- Supports Resident Keys (discoverable credentials) for passwordless authentication
- Maintains challenges locally per connection
- Uses SQLite database for persistent storage of users and credentials
- Enables true passwordless authentication where users don't need to enter a username
"""

from pathlib import Path

import db
import uuid7
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from passkeyauth.passkey import Passkey

STATIC_DIR = Path(__file__).parent.parent / "static"

passkey = Passkey(
    rp_id="localhost",
    rp_name="Passkey Auth",
    origin="http://localhost:8000",
)

app = FastAPI(title="Passkey Auth")


@app.websocket("/ws/new_user_registration")
async def websocket_register_new(ws: WebSocket):
    """Register a new user and with a new passkey credential."""
    await ws.accept()
    try:
        form = await ws.receive_json()
        user_id = uuid7.create().bytes
        user_name = form["user_name"]
        await register_chat(ws, user_id, username)
        # Store the user in the database
        await db.create_user(user_name, user_id)
        await ws.send_json({"status": "success", "user_id": user_id.hex()})
    except WebSocketDisconnect:
        pass


async def register_chat(ws: WebSocket, user_id: bytes, username: str):
    """Generate registration options and send them to the client."""
    options, challenge = passkey.reg_generate_options(
        user_id=user_id,
        username=username,
    )
    await ws.send_text(options)
    # Wait for the client to use his authenticator to register
    credential = passkey.reg_credential(await ws.receive_json())
    passkey.reg_verify(credential, challenge)


@app.websocket("/ws/authenticate")
async def websocket_authenticate(ws: WebSocket):
    await ws.accept()
    try:
        options = passkey.auth_generate_options()
        await ws.send_json(options)
        # Wait for the client to use his authenticator to authenticate
        credential = passkey.auth_credential(await ws.receive_json())
        # Fetch from the database by credential ID
        stored_cred = await db.fetch_credential(credential.raw_id)
        # Verify the credential matches the stored data, that is also updated
        passkey.auth_verify(credential, stored_cred)
        # Update the credential in the database
        await db.update_credential(stored_cred)
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


# Initialize database on startup
db.init_database()

if __name__ == "__main__":
    main()
