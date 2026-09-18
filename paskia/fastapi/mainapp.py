import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, RedirectResponse
from fastapi_vue import env

from paskia import authcode, db, domains, remoteauth
from paskia.bootstrap import bootstrap_if_needed
from paskia.db.background import start_background, stop_background
from paskia.db.lifecycle import kanta
from paskia.fastapi import admin, api, auth_host, oid, ws
from paskia.fastapi.admin.adminapp import adminapp
from paskia.fastapi.dispatch import DispatchMiddleware

# Import frontend instance
from paskia.fastapi.front import frontend
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import passphrase, vitedev
from paskia.util.runtime import serve_config

# Path to examples/index.html when running from source tree
_EXAMPLES_DIR = Path(__file__).parent.parent.parent / "examples"


@asynccontextmanager
async def lifespan(app: FastAPI):  # pragma: no cover - startup path
    """Application lifespan: open the combined database and build the domain registry.

    Process-global serve parameters (listen endpoints, save flag) are passed
    via the PASKIA_CONFIG JSON env variable (set by the CLI entrypoint) so
    that uvicorn reload / multiprocess workers derive site URLs the same
    way. With the save flag set, the listen endpoints are persisted here —
    the CLI never opens the database read-write. Domain configuration is
    read from the database.
    """
    cfg = serve_config()
    domains.configure(listen=cfg.listen)

    await asyncio.to_thread(
        Path(kanta.filename).parent.mkdir, parents=True, exist_ok=True
    )
    async with kanta:
        if cfg.save:
            with kanta.transaction("serve:save_listen"):
                db.data().config.listen = cfg.listen
        try:
            domains.init_registry(db.data().config)
            await remoteauth.init()
            await authcode.start()
        except ValueError as e:
            logging.error(f"⚠️ {e}")
            # Re-raise to fail fast
            raise

        await bootstrap_if_needed()
        await frontend.load()
        await start_background()
        yield
        await stop_background()
        await authcode.stop()


app = FastAPI(
    lifespan=lifespan,
    redirect_slashes=False,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    debug=env.dev,
)

# WebSocket and HTTP access logging is handled by fastapi_vue's ASGI middleware;
# extra details are passed via request.state.log_extra (ASGI scope state).

# Apply redirections to auth-host if configured (deny access to restricted endpoints, remove /auth/)
app.middleware("http")(auth_host.redirect_middleware)

# Domain dispatch must be the outermost application middleware: everything
# below it (including the auth-host redirects) uses the current domain.
app.add_middleware(DispatchMiddleware)

app.mount("/auth/api/admin/", admin.app)
app.mount("/auth/api/", api.app)
app.mount("/auth/ws/", ws.app)
app.mount("/auth/oidc/", oid.app)


# OIDC Well-Known endpoints (must be at site root)
@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request):
    """OpenID Connect Discovery document."""
    # Build issuer URL from request
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("host", request.url.netloc)
    issuer = f"{scheme}://{host}"

    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/auth/restricted/oidc",
        "token_endpoint": f"{issuer}/auth/oidc/token",
        "userinfo_endpoint": f"{issuer}/auth/oidc/userinfo",
        "jwks_uri": f"{issuer}/auth/oidc/keys",
        "backchannel_logout_supported": True,
        "backchannel_logout_session_supported": True,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub",
            "name",
            "preferred_username",
            "email",
            "picture",
            "groups",
            "sid",
        ],
    }


@app.get("/.well-known/webauthn")
async def webauthn_related_origins(request: Request):
    """WebAuthn Related Origin Requests discovery document.

    Served on the domain's rp-id site; lists the domain's related origins
    (other domains) that may assert this rp-id. 404 when the domain has no
    related origins.
    """
    related = request.state.domain.related_origins
    if not related:
        raise HTTPException(status_code=404)
    return {"origins": related}


@app.get("/auth/restricted/iframe")
@app.get("/auth/restricted/oidc")
async def restricted_view(request: Request):
    """Serve the restricted/authentication UI for iframe or OpenID Connect."""
    return await vitedev.handle(request, frontend, "/auth/restricted/")


# Navigable URLs are defined here. We support both / and /auth/ as the base path
# / is used on a dedicated auth site, /auth/ on app domains with auth


@app.get("/")
@app.get("/auth/")
async def frontapp(request: Request, response: Response, auth=AUTH_COOKIE):
    """Serve the user profile app.

    The frontend handles mode detection (host mode vs full profile) based on settings.
    Access control is handled via APIs.
    """
    return await vitedev.handle(request, frontend, "/auth/")


@app.get("/admin", include_in_schema=False)
@app.get("/auth/admin", include_in_schema=False)
async def admin_root_redirect():
    return RedirectResponse(
        f"{domains.current_domain().ui_base_path}admin/", status_code=307
    )


@app.get("/admin/", include_in_schema=False)
@app.get("/auth/admin/", include_in_schema=False)
async def admin_root(request: Request, auth=AUTH_COOKIE):
    return await adminapp(request, auth)  # Delegated to admin app


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
frontend.route(app, "/")


# Note: this catch-all handler must be the last route defined
@app.get("/{token}")
@app.get("/auth/{token}")
async def token_link(request: Request, token: str):
    """Serve the reset app for reset tokens (password reset / device addition).

    The frontend will validate the token via /auth/api/token-info.
    """
    if not passphrase.is_well_formed(token):
        raise HTTPException(status_code=404)

    return await vitedev.handle(request, frontend, "/int/reset/")
