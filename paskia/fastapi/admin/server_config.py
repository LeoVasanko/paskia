from fastapi import Body, FastAPI, HTTPException, Request

from paskia import db
from paskia.db.structs import Config
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.session import AUTH_COOKIE
from paskia.globals import passkey
from paskia.sansio import Passkey
from paskia.util import hostutil
from paskia.util.runtime import update_runtime_config

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

install_error_handlers(app)


@app.get("/")
async def admin_get_server_config(
    request: Request,
    auth=AUTH_COOKIE,
):
    """Get current server configuration (master admin only)."""
    await authz.verify(auth, ["auth:admin"], host=request.headers.get("host"))
    pk = passkey.instance
    config = db.data().config
    return {
        "rp_name": pk.rp_name,
        "auth_host": config.auth_host or "",
        "origins": list(pk.allowed_origins) if pk.allowed_origins else [],
    }


@app.patch("/")
async def admin_update_server_config(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update server configuration (master admin only).

    Updates rp_name, auth_host, and origins in both the runtime Passkey
    instance and the persisted database config.
    """
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    config = db.data().config
    pk = passkey.instance

    rp_name = payload.get("rp_name", "").strip() or None
    auth_host = payload.get("auth_host", "").strip() or None
    raw_origins = payload.get("origins", [])
    origins = [
        hostutil.normalize_origin(o.strip()) for o in raw_origins if o.strip()
    ] or None

    # Normalize auth_host and origins (matching CLI startup behavior)
    if auth_host:
        try:
            hostutil.validate_auth_host(auth_host, config.rp_id)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    auth_host, origins = hostutil.normalize_auth_host_and_origins(auth_host, origins)

    # Validate origins against the current rp_id
    if origins:
        for o in origins:
            Passkey(rp_id=config.rp_id, origins=[o])  # validates or raises

    # Update runtime Passkey instance
    pk.rp_name = rp_name or config.rp_id
    pk.allowed_origins = set(origins) if origins else None

    # Persist to database
    new_config = Config(
        rp_id=config.rp_id,
        rp_name=rp_name,
        auth_host=auth_host,
        origins=origins,
        listen=config.listen,
    )
    db.update_config(new_config)
    update_runtime_config(new_config)
    return {"status": "ok"}
