import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from passkey.util import passphrase

from ..globals import passkey as global_passkey
from . import admin, api, authz, ws

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
app.mount("/auth/ws", ws.app)
app.mount("/auth/admin", admin.app)
app.mount("/auth/api", api.app)


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


# Serve static files
app.mount(
    "/auth/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static assets"
)


@app.get("/auth/")
async def redirect_to_index():
    """Serve the main authentication app."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/auth/{reset_token}")
async def reset_authentication(request: Request, reset_token: str):
    """Validate reset token and redirect with it as query parameter (no cookies).

    After validation we 303 redirect to /auth/?reset=<token>. The frontend will:
    - Read the token from location.search
    - Use it via Authorization header or websocket query param
    - history.replaceState to remove it from the address bar/history
    """
    if not passphrase.is_well_formed(reset_token):
        raise HTTPException(status_code=404)
    origin = global_passkey.instance.origin
    # Do not verify existence/expiry here; frontend + user-info endpoint will handle invalid tokens.
    url = f"{origin}/auth/?reset={reset_token}"
    return RedirectResponse(url=url, status_code=303)


@app.get("/auth/forward-auth")
async def forward_authentication(request: Request, perm=Query(None), auth=Cookie(None)):
    """A validation endpoint to use with Caddy forward_auth or Nginx auth_request.

    Query Params:
    - perm: repeated permission IDs the authenticated user must possess (ALL required).

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
