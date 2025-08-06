import contextlib
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Cookie, FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ..authsession import get_session
from ..db import db
from . import ws
from .api import register_api_routes
from .reset import register_reset_routes

STATIC_DIR = Path(__file__).parent.parent / "frontend-build"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Test if we have a database already initialized, otherwise use SQL
    try:
        db.instance
    except RuntimeError:
        from ..db import sql

        await sql.init()

    yield


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
async def forward_authentication(request: Request, auth=Cookie(None)):
    """A validation endpoint to use with Caddy forward_auth or Nginx auth_request."""
    if auth:
        with contextlib.suppress(ValueError):
            s = await get_session(auth)
            # If authenticated, return a success response
            if s.info and s.info["type"] == "authenticated":
                return Response(
                    status_code=204,
                    headers={
                        "x-auth-user-uuid": str(s.user_uuid),
                    },
                )

    # Serve the index.html of the authentication app if not authenticated
    return FileResponse(
        STATIC_DIR / "index.html",
        status_code=401,
        headers={"www-authenticate": "PrivateToken"},
    )


# Serve static files
app.mount(
    "/auth/assets", StaticFiles(directory=STATIC_DIR / "assets"), name="static assets"
)


@app.get("/auth/")
async def redirect_to_index():
    """Serve the main authentication app."""
    return FileResponse(STATIC_DIR / "index.html")


# Register API routes
register_api_routes(app)
register_reset_routes(app)
