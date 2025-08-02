"""
Minimal FastAPI WebAuthn server with WebSocket support for passkey registration and authentication.

This module provides a simple WebAuthn implementation that:
- Uses WebSocket for real-time communication
- Supports Resident Keys (discoverable credentials) for passwordless authentication
- Maintains challenges locally per connection
- Uses async SQLite database for persistent storage of users and credentials
- Enables true passwordless authentication where users don't need to enter a user_name
"""

import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, FastAPI, Request, Response
from fastapi.responses import (
    FileResponse,
)
from fastapi.staticfiles import StaticFiles

from ..db import sql
from . import session, ws
from .api import register_api_routes
from .reset import register_reset_routes

STATIC_DIR = Path(__file__).parent.parent / "frontend-build"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await sql.init_database()
    yield


app = FastAPI(lifespan=lifespan)

# Mount the WebSocket subapp
app.mount("/auth/ws", ws.app)

# Register API routes
register_api_routes(app)
register_reset_routes(app)


@app.get("/auth/forward-auth")
async def forward_authentication(request: Request, auth=Cookie(None)):
    """A validation endpoint to use with Caddy forward_auth or Nginx auth_request."""
    with contextlib.suppress(ValueError):
        s = await session.get_session(auth)
        # If authenticated, return a success response
        if s.info and s.info["type"] == "authenticated":
            return Response(
                status_code=204,
                headers={
                    "x-auth-user-uuid": str(s.user_uuid),
                },
            )

    # Serve the index.html of the authentication app if not authenticated
    return FileResponse(
        STATIC_DIR / "index.html",
        status_code=401,
        headers={"www-authenticate": "PrivateToken"},
    )


# Serve static files
app.mount(
    "/auth/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static assets"
)


@app.get("/auth/")
async def redirect_to_index():
    """Serve the main authentication app."""
    return FileResponse(STATIC_DIR / "index.html")


def main():
    """Entry point for the application"""
    import uvicorn

    uvicorn.run(
        "passkey.fastapi.main:app",
        host="localhost",
        port=4401,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    main()
