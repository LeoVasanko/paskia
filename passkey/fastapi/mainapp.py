import logging
import os
from contextlib import asynccontextmanager

from fastapi import Cookie, FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from passkey.util import frontend, hostutil, passphrase

from . import admin, api, ws


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
async def frontapp():
    return FileResponse(frontend.file("index.html"))


@app.get("/admin", include_in_schema=False)
@app.get("/auth/admin", include_in_schema=False)
async def admin_root_redirect():
    return RedirectResponse(f"{hostutil.ui_base_path()}admin/", status_code=307)


@app.get("/admin/", include_in_schema=False)
async def admin_root(auth=Cookie(None)):
    return await admin.adminapp(auth)  # Delegate to handler of /auth/admin/


@app.get("/{reset}")
@app.get("/auth/{reset}")
async def reset_link(reset: str):
    """Serve the SPA directly with an injected reset token."""
    if not passphrase.is_well_formed(reset):
        raise HTTPException(status_code=404)
    return FileResponse(frontend.file("reset", "index.html"))


@app.get("/restricted", include_in_schema=False)
@app.get("/auth/restricted", include_in_schema=False)
async def restricted_view():
    return FileResponse(frontend.file("restricted", "index.html"))
