"""Satellite link management API — master admin only, both roles.

**Upstream role** (``/satellites``): mint registration offers (RAM-only,
short-lived, single-use initial keys shown once inside a wss link URL),
list registered links with their live state, adjust a link's scope
(pushed over the live link — registration is once-only) and revoke links
(drops the satellite's connections).

**Satellite role** (``/uplinks``): register an uplink from a pasted link
URL (the online handshake runs synchronously here — the same path the
``paskia satellite`` CLI uses), list uplinks with their live replica
state, and unlink (drops the uplink and every domain it serves).
"""

from urllib.parse import urlsplit

from fastapi import Body, FastAPI, Request

from paskia import db, domains, satellite
from paskia.fastapi import authz, sync
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE

links_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
uplinks_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_error_handlers(links_app)
install_error_handlers(uplinks_app)


def _check_scope(rp_ids) -> list[str]:
    """Validate a link scope: existing authoritative domains with an auth
    host (satellite users' account pages live there). Empty is allowed —
    register first, scope later."""
    clean: list[str] = []
    for raw in rp_ids or []:
        rp_id = str(raw).strip().lower()
        if not rp_id or rp_id in clean:
            continue
        domain = db.data().config.domains.get(rp_id)
        if domain is None:
            raise ValueError(f"Domain {rp_id} not found")
        if domain.remote is not None:
            raise ValueError(
                f"Domain '{rp_id}' is itself satellite-served — "
                "satellites cannot be nested"
            )
        if domains.auth_host_url(domain) is None:
            raise ValueError(
                f"Domain '{rp_id}' must mark an auth host before satellites "
                "can serve it"
            )
        clean.append(rp_id)
    return clean


def _base_url(request: Request, rp_ids: list[str]) -> str:
    """The instance URL the link URL points at: the first scoped domain's
    auth host, else the host the admin is using. Any host of this instance
    serves the sync endpoint — it is not host-dispatched."""
    for rp_id in rp_ids:
        domain = db.data().config.domains[rp_id]
        if url := domains.auth_host_url(domain):
            return url
    return request.state.domain.site_url


# -------------------------------------------------------------------------
# Upstream role: links to satellites
# -------------------------------------------------------------------------


@links_app.get("/")
async def admin_list_links(request: Request, auth=AUTH_COOKIE):
    """List registered satellite links with their live connection state."""
    await authz.verify(auth, ["auth:admin"], host=request.headers.get("host"))
    status = sync.links_status()
    return MsgspecResponse(
        [
            {
                "id": link_id,
                "label": link.label,
                "rp_ids": sorted(link.rp_ids),
                "created": link.created,
                "connected": link_id in status,
                "rejected": status.get(link_id, {}).get("rejected") or {},
            }
            for link_id, link in db.data().satellite_links.items()
        ]
    )


@links_app.post("/")
async def admin_create_offer(
    request: Request, payload: dict = Body(...), auth=AUTH_COOKIE
):
    """Mint a registration offer; the link URL is shown once and expires."""
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    rp_ids = _check_scope(payload.get("rp_ids"))
    return {
        "url": sync.create_offer(rp_ids, _base_url(request, rp_ids)),
        "expires_in": sync.OFFER_TTL,
    }


@links_app.patch("/{link_id}")
async def admin_update_link_scope(
    link_id: str, request: Request, payload: dict = Body(...), auth=AUTH_COOKIE
):
    """Adjust a link's scope; the new domain set is pushed over the live
    link (no new registration)."""
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    rp_ids = _check_scope(payload.get("rp_ids"))
    db.set_satellite_link_scope(link_id, rp_ids, ctx=ctx)
    sync.push_link_domains(link_id)
    return {"status": "ok"}


@links_app.delete("/{link_id}")
async def admin_delete_link(link_id: str, request: Request, auth=AUTH_COOKIE):
    """Revoke a satellite link; its live connections are dropped, and the
    satellite unlinks its side on the policy close."""
    ctx = await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    db.delete_satellite_link(link_id, ctx=ctx)
    await sync.close_link(link_id)
    return {"status": "ok"}


# -------------------------------------------------------------------------
# Satellite role: uplinks
# -------------------------------------------------------------------------


def _uplink_domains_of(uplink_id: str) -> list[str]:
    return sorted(
        rp_id
        for rp_id, d in db.data().config.domains.items()
        if d.remote is not None and d.remote.link == uplink_id
    )


def _host_port(url: str) -> tuple[str, int | None] | None:
    parts = urlsplit(url)
    if not parts.hostname:
        return None
    port = parts.port or {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(
        parts.scheme
    )
    return parts.hostname.lower().rstrip("."), port


def _points_to_self(request: Request, base_url: str) -> bool:
    local_urls = [f"{request.url.scheme}://{request.headers.get('host', '')}"]
    for domain in domains.registry().domains:
        if domain.remote is not None:
            continue
        local_urls.append(domain.site_url)
        if auth_url := domains.auth_host_url(domain.config):
            local_urls.append(auth_url)
    return _host_port(base_url) in {
        endpoint for url in local_urls if (endpoint := _host_port(url)) is not None
    }


@uplinks_app.get("/")
async def admin_list_uplinks(request: Request, auth=AUTH_COOKIE):
    """List uplinks with the domains they serve and live replica state."""
    await authz.verify(auth, ["auth:admin"], host=request.headers.get("host"))
    replicas = satellite.manager.replicas
    return MsgspecResponse(
        [
            {
                "id": uplink_id,
                "url": uplink.url,
                "created": uplink.created,
                "domains": _uplink_domains_of(uplink_id),
                "connected": bool(
                    (replica := replicas.get(uplink_id)) and replica.connected
                ),
                "available": bool(
                    (replica := replicas.get(uplink_id)) and replica.available()
                ),
            }
            for uplink_id, uplink in db.data().uplinks.items()
        ]
    )


@uplinks_app.post("/")
async def admin_register_uplink(
    request: Request, payload: dict = Body(...), auth=AUTH_COOKIE
):
    """Register an uplink from a pasted link URL — the full handshake runs
    here, so failures (expired URL, unreachable upstream, rejected domains)
    come back as the response."""
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    url = str(payload.get("url") or "")
    base_url, _ = satellite.parse_link_url(url)
    if _points_to_self(request, base_url):
        raise ValueError(
            "This link points back to this instance. "
            "A satellite must connect to a different master instance."
        )
    try:
        return await satellite.register_uplink(url)
    except RuntimeError as e:
        raise ValueError(str(e)) from e


@uplinks_app.delete("/{uplink_id}")
async def admin_unlink_uplink(uplink_id: str, request: Request, auth=AUTH_COOKIE):
    """Unlink an uplink: drop it and every domain it serves."""
    await authz.verify(
        auth, ["auth:admin"], host=request.headers.get("host"), max_age="5m"
    )
    if uplink_id not in db.data().uplinks:
        raise ValueError("Uplink not found")
    await satellite.manager.unlink(uplink_id)
    return {"status": "ok"}
