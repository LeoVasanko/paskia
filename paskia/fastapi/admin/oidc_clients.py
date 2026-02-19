from uuid import UUID

from fastapi import Body, FastAPI, HTTPException, Request

from paskia import db
from paskia.db.operations import _UNSET
from paskia.db.structs import Client
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import permutil

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

install_error_handlers(app)


def master_admin(ctx) -> bool:
    return any(p.scope == "auth:admin" for p in ctx.permissions)


@app.post("/")
async def admin_create_oidc_client(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Create a new OIDC client (master admin only)."""
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )
    if not master_admin(ctx):
        raise authz.AuthException(
            status_code=403,
            detail="Only master admin can manage OIDC clients",
            mode="forbidden",
        )

    # Client ID and secret hash are generated client-side
    client_id = payload.get("client_id", "").strip()
    secret_hash_hex = payload.get("secret_hash", "").strip()
    name = payload.get("name", "").strip()
    redirect_uris = payload.get("redirect_uris", [])
    backchannel_logout_uri = payload.get("backchannel_logout_uri")
    if isinstance(backchannel_logout_uri, str):
        backchannel_logout_uri = backchannel_logout_uri.strip() or None

    if not client_id or not secret_hash_hex:
        raise ValueError("client_id and secret_hash are required")

    try:
        client_uuid = UUID(client_id)
    except (ValueError, AttributeError):
        raise ValueError("client_id must be a valid UUID")

    try:
        secret_hash = bytes.fromhex(secret_hash_hex)
    except ValueError:
        raise ValueError("secret_hash must be a hex-encoded SHA-256 hash")
    if len(secret_hash) != 32:
        raise ValueError("secret_hash must be a SHA-256 hash (32 bytes)")

    if not isinstance(redirect_uris, list):
        raise ValueError("redirect_uris must be a list")

    # Validate redirect URIs
    for uri in redirect_uris:
        if not isinstance(uri, str) or not uri.startswith("http"):
            raise ValueError(f"Invalid redirect URI: {uri}")

    if backchannel_logout_uri and not backchannel_logout_uri.startswith("http"):
        raise ValueError("backchannel_logout_uri must be an HTTP(S) URL")

    client = Client(
        client_secret_hash=secret_hash,
        name=name,
        redirect_uris=redirect_uris,
        backchannel_logout_uri=backchannel_logout_uri,
    )
    client.uuid = client_uuid

    db.create_oid_client(client, ctx=ctx)

    return {"status": "ok", "client_id": str(client.uuid)}


@app.patch("/{client_uuid}")
async def admin_update_oidc_client(
    client_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update an OIDC client's name and redirect URIs (master admin only)."""
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )
    if not master_admin(ctx):
        raise authz.AuthException(
            status_code=403,
            detail="Only master admin can manage OIDC clients",
            mode="forbidden",
        )

    name = payload.get("name", "").strip() if "name" in payload else None
    redirect_uris = payload.get("redirect_uris") if "redirect_uris" in payload else None
    secret_hash_hex = (
        payload.get("secret_hash", "").strip() if "secret_hash" in payload else None
    )
    backchannel_logout_uri = (
        payload.get("backchannel_logout_uri")
        if "backchannel_logout_uri" in payload
        else _UNSET
    )
    if isinstance(backchannel_logout_uri, str):
        backchannel_logout_uri = backchannel_logout_uri.strip() or None

    if name is not None and not name:
        raise ValueError("Client name cannot be empty")

    if redirect_uris is not None:
        if not isinstance(redirect_uris, list):
            raise ValueError("redirect_uris must be a list")
        # Validate redirect URIs
        for uri in redirect_uris:
            if not isinstance(uri, str) or not uri.startswith("http"):
                raise ValueError(f"Invalid redirect URI: {uri}")

    if (
        backchannel_logout_uri is not _UNSET
        and backchannel_logout_uri
        and not backchannel_logout_uri.startswith("http")
    ):
        raise ValueError("backchannel_logout_uri must be an HTTP(S) URL")

    secret_hash = None
    if secret_hash_hex:
        try:
            secret_hash = bytes.fromhex(secret_hash_hex)
        except ValueError:
            raise ValueError("secret_hash must be a hex-encoded SHA-256 hash")
        if len(secret_hash) != 32:
            raise ValueError("secret_hash must be a SHA-256 hash (32 bytes)")

    try:
        db.update_oid_client(
            client_uuid,
            name=name,
            redirect_uris=redirect_uris,
            secret_hash=secret_hash,
            backchannel_logout_uri=backchannel_logout_uri,
            ctx=ctx,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"status": "ok"}


@app.post("/{client_uuid}/reset-secret")
async def admin_reset_oidc_client_secret(
    client_uuid: UUID,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Reset an OIDC client's secret (master admin only).

    The new secret is generated client-side; only the SHA-256 hash is sent.
    """
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )
    if not master_admin(ctx):
        raise authz.AuthException(
            status_code=403,
            detail="Only master admin can manage OIDC clients",
            mode="forbidden",
        )

    secret_hash_hex = payload.get("secret_hash", "").strip()
    if not secret_hash_hex:
        raise ValueError("secret_hash is required")
    try:
        secret_hash = bytes.fromhex(secret_hash_hex)
    except ValueError:
        raise ValueError("secret_hash must be a hex-encoded SHA-256 hash")
    if len(secret_hash) != 32:
        raise ValueError("secret_hash must be a SHA-256 hash (32 bytes)")

    try:
        db.reset_oid_client_secret(client_uuid, secret_hash, ctx=ctx)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"status": "ok"}


@app.delete("/{client_uuid}")
async def admin_delete_oidc_client(
    client_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Delete an OIDC client (master admin only)."""
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )
    if not master_admin(ctx):
        raise authz.AuthException(
            status_code=403,
            detail="Only master admin can manage OIDC clients",
            mode="forbidden",
        )

    try:
        db.delete_oid_client(client_uuid, ctx=ctx)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return {"status": "ok"}
