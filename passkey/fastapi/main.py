"""
Minimal FastAPI WebAuthn server with WebSocket support for passkey registration and authentication.

This module provides a simple WebAuthn implementation that:
- Uses WebSocket for real-time communication
- Supports Resident Keys (discoverable credentials) for passwordless authentication
- Maintains challenges locally per connection
- Uses async SQLite database for persistent storage of users and credentials
- Enables true passwordless authentication where users don't need to enter a user_name
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (
    FastAPI,
    Request,
    Response,
)
from fastapi.responses import (
    FileResponse,
    JSONResponse,
)
from fastapi.staticfiles import StaticFiles

from ..db import sql
from .api import (
    register_api_routes,
    validate_token,
)
from .reset import register_reset_routes
from .ws import ws_app

STATIC_DIR = Path(__file__).parent.parent / "frontend-build"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await sql.init_database()
    yield


app = FastAPI(lifespan=lifespan)

# Mount the WebSocket subapp
app.mount("/auth/ws", ws_app)

# Register API routes
register_api_routes(app)
register_reset_routes(app)


@app.get("/auth/forward-auth")
async def forward_authentication(request: Request):
    """A verification endpoint to use with Caddy forward_auth or Nginx auth_request."""
    # Create a dummy response object for internal validation (we won't use it for cookies)
    response = Response()

    result = await validate_token(request, response)
    if result.get("status") != "success":
        # Serve the index.html of the authentication app if not authenticated
        return FileResponse(
            STATIC_DIR / "index.html",
            status_code=401,
            headers={"www-authenticate": "PrivateToken"},
        )

    # If authenticated, return a success response
    return Response(
        status_code=204,
        headers={"x-auth-user-id": result["user_id"]},
    )


# Serve static files
app.mount(
    "/auth/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static assets"
)


@app.get("/auth")
async def redirect_to_index():
    """Serve the main authentication app."""
    return FileResponse(STATIC_DIR / "index.html")


# Catch-all route for SPA - serve index.html for all non-API routes
@app.get("/{path:path}")
async def spa_handler(request: Request, path: str):
    """Serve the Vue SPA for all routes (except API and static)"""
    if "text/html" not in request.headers.get("accept", ""):
        return JSONResponse({"error": "Not Found"}, status_code=404)
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
