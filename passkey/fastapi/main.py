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
from fastapi import (
    Path as FastAPIPath,
)
from fastapi.responses import (
    FileResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles

from ..db import sql
from .api_handlers import (
    delete_credential,
    get_user_credentials,
    get_user_info,
    logout,
    refresh_token,
    set_session,
    validate_token,
)
from .reset_handlers import create_device_addition_link, validate_device_addition_token
from .ws_handlers import ws_app

STATIC_DIR = Path(__file__).parent.parent / "frontend-build"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await sql.init_database()
    yield


app = FastAPI(title="Passkey Auth", lifespan=lifespan)

# Mount the WebSocket subapp
app.mount("/auth/ws", ws_app)





@app.get("/auth/user-info")
async def api_get_user_info(request: Request):
    """Get user information from session cookie."""
    return await get_user_info(request)


@app.get("/auth/user-credentials")
async def api_get_user_credentials(request: Request):
    """Get all credentials for a user using session cookie."""
    return await get_user_credentials(request)


@app.post("/auth/refresh-token")
async def api_refresh_token(request: Request, response: Response):
    """Refresh the session token."""
    return await refresh_token(request, response)


@app.get("/auth/validate-token")
async def api_validate_token(request: Request):
    """Validate a session token and return user info."""
    return await validate_token(request)


@app.get("/auth/forward-auth")
async def forward_authentication(request: Request):
    """A verification endpoint to use with Caddy forward_auth or Nginx auth_request."""
    result = await validate_token(request)
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


@app.post("/auth/logout")
async def api_logout(response: Response):
    """Log out the current user by clearing the session cookie."""
    return await logout(response)


@app.post("/auth/set-session")
async def api_set_session(request: Request, response: Response):
    """Set session cookie using JWT token from request body or Authorization header."""
    return await set_session(request, response)


@app.post("/auth/delete-credential")
async def api_delete_credential(request: Request):
    """Delete a specific credential for the current user."""
    return await delete_credential(request)


@app.post("/auth/create-device-link")
async def api_create_device_link(request: Request):
    """Create a device addition link for the authenticated user."""
    return await create_device_addition_link(request)


@app.post("/auth/validate-device-token")
async def api_validate_device_token(request: Request):
    """Validate a device addition token."""
    return await validate_device_addition_token(request)


@app.get("/auth/{passphrase}")
async def reset_authentication(
    passphrase: str = FastAPIPath(pattern=r"^\w+(\.\w+){2,}$"),
):
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="auth-token",
        value=passphrase,
        httponly=False,
        secure=True,
        samesite="strict",
        max_age=2,
    )
    return response


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
        return Response(content="Not Found", status_code=404)
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
