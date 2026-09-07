"""Domain (rp-id) management API — master admin only.

Each domain is one rp-id with its own rp-name and an origins table of
sign-in sites: entries within the rp-id domain are in-domain sites (one of
which may be marked as the auth host), entries outside it are related
origins on unrelated domains (WebAuthn Related Origin Requests). All
changes are validated cross-domain before being persisted, and the runtime
domain registry is rebuilt after each change so it takes effect
immediately.
"""

from fastapi import Body, FastAPI, Request

from paskia import db, domains
from paskia.db.structs import Config, DomainConfig, OriginEntry
from paskia.fastapi import authz
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE
from paskia.sansio import Passkey
from paskia.util import hostutil
from paskia.util.apistructs import ApiDomain

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

install_error_handlers(app)


def _domain_to_api(domain: domains.Domain) -> ApiDomain:
    return ApiDomain(
        rp_id=domain.rp_id,
        rp_name=domain.rp_name,
        origins=domain.config.origins,
        site_url=domain.site_url,
        auth_site_url=domain.auth_site_url,
        auth_host=domain.own_auth_host,
    )


def _normalize_origins_map(values: dict | None) -> dict[str, bool | OriginEntry]:
    """Normalize an origins object from the admin UI (raises on malformed).

    Keys arrive as bare hosts, wildcard patterns, or full origins; they are
    stored as origins-table keys (https:// omitted). In-domain vs. related
    classification is derived from the rp-id at validation time.
    """
    out: dict[str, bool | OriginEntry] = {}
    for raw_key, raw_props in (values or {}).items():
        key = raw_key.strip()
        if not key:
            continue
        if key != "*" and not hostutil.is_wildcard_pattern(key):
            key = domains.origin_key(hostutil.normalize_origin(key))
        is_auth = raw_props is not True and bool((raw_props or {}).get("auth_host"))
        out[key] = OriginEntry(auth_host=True) if is_auth else True
    return out


def _rebuild_registry() -> None:
    """Rebuild the runtime domain registry from the stored configuration."""
    domains.init_registry(db.data().config)


def _check_not_locking_self_out(
    request: Request,
    rp_id: str,
    domain: DomainConfig,
) -> None:
    """Refuse domain changes that lock the admin out of their current host.

    Applies when the admin edits the domain they are currently using and the
    new config has no auth host (with an auth host, ceremonies move there
    and it is always allowed). The admin's current host must remain able to
    run passkey ceremonies under the new config.
    """
    current: domains.Domain = request.state.domain
    if rp_id != current.rp_id or domains.auth_host_url(domain):
        return
    raw_host = (request.headers.get("host") or "").rstrip(".")
    if not raw_host:
        return
    in_domain, related = domains.partition_origins(rp_id, domain.origins)
    probe = Passkey(
        rp_id=rp_id,
        origins=[domains.origin_url(k) for k in in_domain],
        related_origins=[domains.origin_url(k) for k in related],
    )
    for scheme in ("https", "http"):
        try:
            probe.validate_origin(f"{scheme}://{raw_host}")
            return  # Current host still works — no lockout
        except ValueError:
            pass
    raise ValueError(
        f"This change would lock you out: '{raw_host}' could no longer "
        f"run passkey ceremonies for domain '{rp_id}'. Add it to the "
        "allowed origins (or mark an auth host) before saving."
    )


@app.get("/")
async def admin_list_domains(request: Request, auth=AUTH_COOKIE):
    """List all domains with derived URLs (master admin only)."""
    await authz.verify(auth, ["auth:admin"], host=request.headers.get("host"))
    registry = domains.registry()
    return MsgspecResponse([_domain_to_api(domain) for domain in registry.domains])


@app.post("/")
async def admin_create_domain(
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Add a new domain (master admin only, recent authentication required)."""
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )

    rp_id = (payload.get("rp_id") or "").strip().lower()
    if not rp_id:
        raise ValueError("rp_id is required")
    new = DomainConfig(
        rp_name=(payload.get("rp_name") or "").strip() or None,
        origins=_normalize_origins_map(payload.get("origins")),
    )

    config = db.data().config
    # Validate the would-be combined configuration before persisting
    domains.validate_config(
        Config(domains={**config.domains, rp_id: new}, listen=config.listen)
    )

    db.create_domain(rp_id, new, ctx=ctx)
    _rebuild_registry()
    return {"status": "ok"}


@app.patch("/{rp_id}")
async def admin_update_domain(
    rp_id: str,
    request: Request,
    payload: dict = Body(...),
    auth=AUTH_COOKIE,
):
    """Update a domain's rp_name, origins and related origins (replaced
    wholesale).

    The rp-id itself is immutable: credentials are stamped with it.
    """
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )

    config = db.data().config
    if rp_id not in config.domains:
        raise ValueError(f"Domain {rp_id} not found")

    updated = DomainConfig(
        rp_name=(payload.get("rp_name") or "").strip() or None,
        origins=_normalize_origins_map(payload.get("origins")),
    )
    would_be = Config(
        domains={k: updated if k == rp_id else v for k, v in config.domains.items()},
        listen=config.listen,
    )
    domains.validate_config(would_be)
    _check_not_locking_self_out(request, rp_id, updated)

    db.update_domain(
        rp_id,
        rp_name=updated.rp_name,
        origins=updated.origins,
        ctx=ctx,
    )
    _rebuild_registry()
    return {"status": "ok"}


@app.delete("/{rp_id}")
async def admin_delete_domain(
    rp_id: str,
    request: Request,
    auth=AUTH_COOKIE,
):
    """Delete a domain (refused for the last domain or while credentials remain)."""
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    current: domains.Domain = request.state.domain
    if rp_id == current.rp_id:
        raise ValueError(
            "Cannot delete the domain you are currently using — authenticate "
            "on another domain first"
        )
    db.delete_domain(rp_id, ctx=ctx)
    _rebuild_registry()
    return {"status": "ok"}
