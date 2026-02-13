import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi_vue import Frontend

from paskia import globals
from paskia.db import start_background, stop_background
from paskia.db.logging import configure_db_logging
from paskia.fastapi import admin, api, auth_host, ws
from paskia.__main__ import DEVMODE
from paskia.fastapi.logging import AccessLogMiddleware, configure_access_logging
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import hostutil, passphrase, vitedev

# Configure custom logging
configure_access_logging()
configure_db_logging()

_access_logger = logging.getLogger("paskia.access")

# Vue Frontend static files
frontend = Frontend(
    Path(__file__).parent.parent / "frontend-build",
    cached=["/auth/assets/"],
    favicon="/paskia.webp",
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

    # Restore uvicorn info logging (suppressed during startup in dev mode)
    # Keep uvicorn.error at WARNING to suppress WebSocket "connection open/closed" messages
    if app.debug:
        logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    await frontend.load()
    await start_background()
    yield
    await stop_background()


app = FastAPI(
    lifespan=lifespan,
    redirect_slashes=False,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    debug=DEVMODE,
)

# Custom access logging (uvicorn's access_log is disabled)
app.add_middleware(AccessLogMiddleware)

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


# Frontend static files - must be before /{token} catch-all routes
# (actual routes registered during lifespan after frontend.load())
frontend.route(app, "/")


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
