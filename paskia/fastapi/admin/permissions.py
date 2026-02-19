from uuid import UUID

from fastapi import Body, FastAPI, Query, Request

from paskia import db
from paskia.db import Permission as PermDC
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.session import AUTH_COOKIE
from paskia.globals import passkey
from paskia.util import hostutil, permutil, querysafe

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

install_error_handlers(app)


def _validate_permission_domain(domain: str | None) -> None:
    """Validate that domain is rp_id, a subdomain of it, or an OIDC client UUID."""
    if domain is None:
        return

    # Allow OIDC client UUIDs (used for groups claim)
    try:
        client_uuid = UUID(domain)
        if client_uuid in db.data().oidc.clients:
            return
    except ValueError:
        pass

    rp_id = passkey.instance.rp_id
    if domain == rp_id or domain.endswith(f".{rp_id}"):
        return
    raise ValueError(
        f"Domain '{domain}' must be '{rp_id}', its subdomain, or an OIDC client UUID"
    )


def _check_admin_lockout(
    perm_uuid: str, new_domain: str | None, current_host: str | None
) -> None:
    """Check if setting domain on auth:admin would lock out the admin.

    Raises ValueError if this change would result in no auth:admin permissions
    being accessible from the current host.
    """

    normalized_host = hostutil.normalize_host(current_host)
    host_without_port = normalized_host.rsplit(":", 1)[0] if normalized_host else None

    # Get all auth:admin permissions
    all_perms = list(db.data().permissions.values())
    admin_perms = [p for p in all_perms if p.scope == "auth:admin"]

    # Check if at least one auth:admin would remain accessible
    for p in admin_perms:
        # If this is the permission being modified, use the new domain
        domain = new_domain if str(p.uuid) == perm_uuid else p.domain

        # No domain restriction = accessible from anywhere
        if domain is None:
            return

        # Check if domain matches current host
        if domain == normalized_host or domain == host_without_port:
            return

        # Check if domain is a subdomain of current host or vice versa
        if normalized_host and normalized_host.endswith(f".{domain}"):
            return
        if host_without_port and host_without_port.endswith(f".{domain}"):
            return

    raise ValueError(
        f"Setting domain '{new_domain}' on auth:admin permission would lock you out of "
        f"admin access from current host '{current_host}'"
    )


def _check_admin_lockout_on_delete(perm_uuid: str, current_host: str | None) -> None:
    """Check if deleting an auth:admin permission would lock out the admin.

    Raises ValueError if this deletion would result in no auth:admin permissions
    being accessible from the current host.
    """
    normalized_host = hostutil.normalize_host(current_host)
    host_without_port = normalized_host.rsplit(":", 1)[0] if normalized_host else None

    # Get all auth:admin permissions except the one being deleted
    all_perms = list(db.data().permissions.values())
    admin_perms = [
        p for p in all_perms if p.scope == "auth:admin" and str(p.uuid) != perm_uuid
    ]

    # Check if at least one auth:admin would remain accessible
    for p in admin_perms:
        domain = p.domain

        # No domain restriction = accessible from anywhere
        if domain is None:
            return

        # Check if domain matches current host
        if domain == normalized_host or domain == host_without_port:
            return

        # Check if domain is a subdomain of current host or vice versa
        if normalized_host and normalized_host.endswith(f".{domain}"):
            return
        if host_without_port and host_without_port.endswith(f".{domain}"):
            return

    raise ValueError(
        f"Deleting this auth:admin permission would lock you out of "
        f"admin access from current host '{current_host}'"
    )


@app.post("/")
async def admin_create_permission(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )

    scope = payload.get("scope") or payload.get(
        "id"
    )  # Support both for backwards compat
    display_name = payload.get("display_name")
    domain = payload.get("domain") or None  # Treat empty string as None
    if not scope or not display_name:
        raise ValueError("scope and display_name are required")
    querysafe.assert_safe(scope, field="scope")
    _validate_permission_domain(domain)
    db.create_permission(
        PermDC.create(scope=scope, display_name=display_name, domain=domain),
        ctx=ctx,
    )
    return {"status": "ok"}


@app.patch("/{permission_uuid}")
async def admin_update_permission(
    permission_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
    display_name: str | None = Query(None),
    scope: str | None = Query(None),
    domain: str | None = Query(None),
):
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), match=permutil.has_all
    )

    # Get existing permission
    perm = db.data().permissions.get(permission_uuid)

    # Update fields that were provided
    new_scope = scope if scope is not None else perm.scope
    new_display_name = display_name if display_name is not None else perm.display_name
    domain_value = domain if domain else None

    # Sanity check: prevent changing the auth:admin permission scope
    if perm.scope == "auth:admin" and new_scope != "auth:admin":
        raise ValueError("Cannot rename the master admin permission")

    if not new_display_name:
        raise ValueError("display_name is required")
    querysafe.assert_safe(new_scope, field="scope")
    _validate_permission_domain(domain_value)

    # Safety check: prevent admin lockout when setting domain on auth:admin
    if perm.scope == "auth:admin" or new_scope == "auth:admin":
        _check_admin_lockout(str(perm.uuid), domain_value, request.headers.get("host"))

    db.update_permission(
        uuid=perm.uuid,
        scope=new_scope,
        display_name=new_display_name,
        domain=domain_value,
        ctx=ctx,
    )
    return {"status": "ok"}


@app.delete("/{permission_uuid}")
async def admin_delete_permission(
    permission_uuid: UUID,
    request: Request,
    auth=AUTH_COOKIE,
):
    ctx = await authz.verify(
        auth,
        ["auth:admin"],
        host=request.headers.get("host"),
        match=permutil.has_all,
        max_age="5m",
    )

    # Get the permission to check its scope
    perm = db.data().permissions.get(permission_uuid)

    # Sanity check: prevent deleting critical permissions if it would lock out admin
    if perm.scope == "auth:admin":
        _check_admin_lockout_on_delete(str(perm.uuid), request.headers.get("host"))

    db.delete_permission(permission_uuid, ctx=ctx)
    return {"status": "ok"}
