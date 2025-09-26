import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from passkey.util import frontend, passphrase

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


@app.get("/")
async def frontapp_redirect(request: Request):
    """Redirect root (in case accessed on backend) to the main authentication app."""
    return RedirectResponse(request.url_for("frontapp"), status_code=303)


@app.get("/auth/")
async def frontapp():
    """Serve the main authentication app."""
    return FileResponse(frontend.file("index.html"))


@app.get("/auth/{reset}")
async def reset_link(request: Request, reset: str):
    """Pretty URL for reset links."""
    if reset == "admin":
        # Admin app missing trailing slash lands here, be friendly to user
        return RedirectResponse(request.url_for("adminapp"), status_code=303)
    if not passphrase.is_well_formed(reset):
        raise HTTPException(status_code=404)
    url = request.url_for("frontapp").include_query_params(reset=reset)
    return RedirectResponse(url, status_code=303)
