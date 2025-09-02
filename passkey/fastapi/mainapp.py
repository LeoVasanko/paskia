import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from passkey.util import passphrase

from . import admin, api, ws

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
app.mount("/auth/admin", admin.app)
app.mount("/auth/api", api.app)
app.mount("/auth/ws", ws.app)
app.mount("/auth/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="assets")


@app.get("/auth/")
async def frontend():
    """Serve the main authentication app."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/auth/{reset}")
async def reset_authentication(request: Request, reset: str):
    """Validate reset token and redirect with it as query parameter (no cookies).

    After validation we 303 redirect to /auth/?reset=<token>. The frontend will:
    - Read the token from location.search
    - Use it via Authorization header or websocket query param
    - history.replaceState to remove it from the address bar/history
    """
    if not passphrase.is_well_formed(reset):
        raise HTTPException(status_code=404)
    return RedirectResponse(request.url_for("frontend", reset=reset), status_code=303)


## forward-auth endpoint moved to /auth/api/forward in api.py
