import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from paskia.fastapi import admin, api, auth_host, ws
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import frontend, hostutil, passphrase


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover - startup path
    """Application lifespan to ensure globals (DB, passkey) are initialized in each process.

    We populate configuration from environment variables (set by the CLI entrypoint)
    so that uvicorn reload / multiprocess workers inherit the settings.
    """
    from paskia import globals

    rp_id = os.getenv("PASKIA_RP_ID", "localhost")
    rp_name = os.getenv("PASKIA_RP_NAME") or None
    origin = os.getenv("PASKIA_ORIGIN") or None
    default_admin = (
        os.getenv("PASKIA_DEFAULT_ADMIN") or None
    )  # still passed for context
    default_org = os.getenv("PASKIA_DEFAULT_ORG") or None
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

app.mount("/auth/api/admin/", admin.app)
app.mount("/auth/api/", api.app)
app.mount("/auth/ws/", ws.app)

# In dev mode (PASKIA_DEVMODE=1), Vite serves assets directly; skip static files mount
if not frontend.is_dev_mode():
    app.mount(
        "/auth/assets/",
        StaticFiles(directory=frontend.file("auth", "assets")),
        name="assets",
    )


@app.get("/auth/restricted/")
async def restricted_view():
    """Serve the restricted/authentication UI for iframe embedding."""
    return Response(*await frontend.read("/auth/restricted/index.html"))


# Navigable URLs are defined here. We support both / and /auth/ as the base path
# / is used on a dedicated auth site, /auth/ on app domains with auth


@app.get("/")
@app.get("/auth/")
async def frontapp(request: Request, response: Response, auth=AUTH_COOKIE):
    """Serve the user profile app.

    The frontend handles mode detection (host mode vs full profile) based on settings.
    Access control is handled via APIs.
    """
    return Response(*await frontend.read("/auth/index.html"))


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
    return Response(*await frontend.read("/int/reset/index.html"))
