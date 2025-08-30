import contextlib
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..authsession import get_session
from . import authz, ws
from .api import register_api_routes
from .reset import register_reset_routes

STATIC_DIR = Path(__file__).parent.parent / "frontend-build"


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover - startup path
    """Application lifespan to ensure globals (DB, passkey) are initialized in each process.

    We populate configuration from environment variables (set by the CLI entrypoint)
    so that uvicorn reload / multiprocess workers inherit the settings.
    """
    from .. import globals

    rp_id = os.getenv("PASSKEY_RP_ID", "localhost")
    rp_name = os.getenv("PASSKEY_RP_NAME") or None
    origin = os.getenv("PASSKEY_ORIGIN") or None
    default_admin = (
        os.getenv("PASSKEY_DEFAULT_ADMIN") or None
    )  # still passed for context
    default_org = os.getenv("PASSKEY_DEFAULT_ORG") or None
    try:
        # CLI (__main__) performs bootstrap once; here we skip to avoid duplicate work
        await globals.init(
            rp_id=rp_id,
            rp_name=rp_name,
            origin=origin,
            default_admin=default_admin,
            default_org=default_org,
            bootstrap=False,
        )
    except ValueError as e:
        logging.error(f"⚠️ {e}")
        # Re-raise to fail fast
        raise
    yield
    # (Optional) add shutdown cleanup here later


app = FastAPI(lifespan=lifespan)


# Global exception handlers
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle ValueError exceptions globally with 400 status code."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle all other exceptions globally with 500 status code."""
    logging.exception("Internal Server Error")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# Mount the WebSocket subapp
app.mount("/auth/ws", ws.app)


@app.get("/auth/forward-auth")
async def forward_authentication(
    request: Request, perm: str | None = None, auth=Cookie(None)
):
    """A validation endpoint to use with Caddy forward_auth or Nginx auth_request.

    Query Params:
    - perm: optional permission ID the authenticated user must possess (role or org).

    Success: 204 No Content with x-auth-user-uuid header.
    Failure (unauthenticated / unauthorized): 4xx with index.html body so the
    client (reverse proxy or browser) can initiate auth flow.
    """
    try:
        s = await authz.verify(auth, perm)
        return Response(
            status_code=204,
            headers={"x-auth-user-uuid": str(s.user_uuid)},
        )
    except HTTPException as e:
        return FileResponse(STATIC_DIR / "index.html", e.status_code)


# Serve static files
app.mount(
    "/auth/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static assets"
)


@app.get("/auth/")
async def redirect_to_index():
    """Serve the main authentication app."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/auth/admin")
async def serve_admin(auth=Cookie(None)):
    """Serve the admin app entry point if an authenticated session exists.

    If no valid authenticated session cookie is present, return a 401 with the
    main app's index.html so the frontend can initiate login/registration flow.
    """
    if auth:
        with contextlib.suppress(ValueError):
            s = await get_session(auth)
            if s.info and s.info.get("type") == "authenticated":
                return FileResponse(STATIC_DIR / "admin" / "index.html")

    # Not authenticated: serve main index with 401
    return FileResponse(
        STATIC_DIR / "index.html",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


# Register API routes
register_api_routes(app)
register_reset_routes(app)
