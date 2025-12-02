import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from passkey.util import frontend, hostutil, passphrase

from . import admin, api, auth_host, ws
from .session import AUTH_COOKIE


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

# Apply redirections to auth-host if configured (deny access to restricted endpoints, remove /auth/)
app.middleware("http")(auth_host.redirect_middleware)

app.mount("/auth/admin/", admin.app)
app.mount("/auth/api/", api.app)
app.mount("/auth/ws/", ws.app)
app.mount(
    "/auth/assets/", StaticFiles(directory=frontend.file("assets")), name="assets"
)

# Navigable URLs are defined here. We support both / and /auth/ as the base path
# / is used on a dedicated auth site, /auth/ on app domains with auth


@app.get("/")
@app.get("/auth/")
async def frontapp(request: Request, response: Response, auth=AUTH_COOKIE):
    """Serve the user profile app.

    Access control is handled via APIs.
    """
    cfg_host = hostutil.configured_auth_host()
    if cfg_host:
        cur_host = hostutil.normalize_host(request.headers.get("host"))
        cfg_normalized = hostutil.normalize_host(cfg_host)
        if cur_host and cfg_normalized and cur_host != cfg_normalized:
            return FileResponse(frontend.file("host", "index.html"))
    return FileResponse(frontend.file("index.html"))


@app.get("/admin", include_in_schema=False)
@app.get("/auth/admin", include_in_schema=False)
async def admin_root_redirect():
    return RedirectResponse(f"{hostutil.ui_base_path()}admin/", status_code=307)


@app.get("/admin/", include_in_schema=False)
async def admin_root(request: Request, auth=AUTH_COOKIE):
    return await admin.adminapp(request, auth)  # Delegated to admin app


# Note: this catch-all handler must be the last route defined
@app.get("/{reset}")
@app.get("/auth/{reset}")
async def reset_link(reset: str):
    """Serve the reset app directly with an injected reset token."""
    if not passphrase.is_well_formed(reset):
        raise HTTPException(status_code=404)
    return FileResponse(frontend.file("reset", "index.html"))
