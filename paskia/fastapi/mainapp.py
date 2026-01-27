import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi_vue import Frontend

from paskia import globals
from paskia.fastapi import admin, api, auth_host, ws
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import hostutil, passphrase, vitedev

# Vue Frontend static files
frontend = Frontend(
    Path(__file__).parent.parent / "frontend-build",
    cached=["/auth/assets/"],
)


# Path to examples/index.html when running from source tree
_EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover - startup path
    """Application lifespan to ensure globals (DB, passkey) are initialized in each process.

    Configuration is passed via PASKIA_CONFIG JSON env variable (set by the CLI entrypoint)
    so that uvicorn reload / multiprocess workers inherit the settings.
    All keys are guaranteed to exist; values are already normalized by __main__.py.
    """

    config = json.loads(os.environ["PASKIA_CONFIG"])

    try:
        # CLI (__main__) performs bootstrap once; here we skip to avoid duplicate work
        await globals.init(
            rp_id=config["rp_id"],
            rp_name=config["rp_name"],
            origins=config["origins"],
            bootstrap=False,
        )
    except ValueError as e:
        logging.error(f"⚠️ {e}")
        # Re-raise to fail fast
        raise

    # Restore info level logging after startup (suppressed during uvicorn init in dev mode)
    if frontend.devmode:
        logging.getLogger("uvicorn").setLevel(logging.INFO)
        logging.getLogger("uvicorn.access").setLevel(logging.INFO)

    await frontend.load()
    yield


app = FastAPI(lifespan=lifespan, redirect_slashes=False)

# Apply redirections to auth-host if configured (deny access to restricted endpoints, remove /auth/)
app.middleware("http")(auth_host.redirect_middleware)

app.mount("/auth/api/admin/", admin.app)
app.mount("/auth/api/", api.app)
app.mount("/auth/ws/", ws.app)


@app.get("/auth/restricted/")
async def restricted_view():
    """Serve the restricted/authentication UI for iframe embedding."""
    return Response(*await vitedev.read("/auth/restricted/index.html"))


# Navigable URLs are defined here. We support both / and /auth/ as the base path
# / is used on a dedicated auth site, /auth/ on app domains with auth


@app.get("/")
@app.get("/auth/")
async def frontapp(request: Request, response: Response, auth=AUTH_COOKIE):
    """Serve the user profile app.

    The frontend handles mode detection (host mode vs full profile) based on settings.
    Access control is handled via APIs.
    """
    return Response(*await vitedev.read("/auth/index.html"))


@app.get("/admin", include_in_schema=False)
@app.get("/auth/admin", include_in_schema=False)
async def admin_root_redirect():
    return RedirectResponse(f"{hostutil.ui_base_path()}admin/", status_code=307)


@app.get("/admin/", include_in_schema=False)
@app.get("/auth/admin/", include_in_schema=False)
async def admin_root(request: Request, auth=AUTH_COOKIE):
    return await admin.adminapp(request, auth)  # Delegated to admin app


@app.get("/auth/examples/", include_in_schema=False)
async def examples_page():
    """Serve examples/index.html when running from source tree.

    This provides a simple test page for API mode authentication flows
    without depending on the Vue frontend build.
    """
    index_file = _EXAMPLES_DIR / "index.html"
    if not index_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="Examples not available (not running from source tree)",
        )
    return FileResponse(index_file, media_type="text/html")


# Note: this catch-all handler must be the last route defined
@app.get("/{token}")
@app.get("/auth/{token}")
async def token_link(token: str):
    """Serve the reset app for reset tokens (password reset / device addition).

    The frontend will validate the token via /auth/api/token-info.
    """
    if not passphrase.is_well_formed(token):
        raise HTTPException(status_code=404)

    return Response(*await vitedev.read("/int/reset/index.html"))


# Final catch-all route for frontend files (keep at end of file)
frontend.route(app, "/")
