from uuid import UUID

from fastapi import FastAPI, Request

from paskia import db
from paskia.fastapi import authz
from paskia.fastapi.admin import (
    oidc_clients,
    orgs,
    permissions,
    roles,
    server_config,
    users,
)
from paskia.fastapi.admin.errors import install_error_handlers
from paskia.fastapi.front import frontend
from paskia.fastapi.response import MsgspecResponse
from paskia.fastapi.session import AUTH_COOKIE
from paskia.util import (
    permutil,
    vitedev,
)
from paskia.util.apistructs import (
    ApiAdminInfo,
    ApiOidcClient,
    ApiOrg,
    ApiOrgResponse,
    ApiPermission,
)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

install_error_handlers(app)
app.mount("/oidc-clients", oidc_clients.app)
app.mount("/orgs", orgs.app)
app.mount("/roles", roles.app)
app.mount("/users", users.app)
app.mount("/permissions", permissions.app)
app.mount("/server-config", server_config.app)


def master_admin(ctx) -> bool:
    return any(p.scope == "auth:admin" for p in ctx.permissions)


def org_admin(ctx, org_uuid: UUID) -> bool:
    return ctx.org.uuid == org_uuid and any(
        p.scope == "auth:org:admin" for p in ctx.permissions
    )


def can_manage_org(ctx, org_uuid: UUID) -> bool:
    return master_admin(ctx) or org_admin(ctx, org_uuid)


@app.get("/")
async def adminapp(request: Request, auth=AUTH_COOKIE):
    return await vitedev.handle(request, frontend, "/auth/admin/")


@app.get("/info")
async def admin_info(request: Request, auth=AUTH_COOKIE):
    ctx = await authz.verify(
        auth,
        ["auth:admin", "auth:org:admin"],
        match=permutil.has_any,
        host=request.headers.get("host"),
    )

    # Orgs
    orgs = list(db.data().orgs.values())
    if not master_admin(ctx):
        # Org admins can only see their own organization
        orgs = [o for o in orgs if o.uuid == ctx.org.uuid]

    def org_to_dict(o):
        roles = o.roles
        return ApiOrgResponse(
            org=ApiOrg.from_db(o),
            permissions={p.uuid: p for p in o.permissions},
            roles={r.uuid: r for r in roles},
            users={u.uuid: u for r in roles for u in r.users},
        )

    orgs_dict = {o.uuid: org_to_dict(o) for o in orgs}

    # Permissions
    perms = db.data().permissions.values() if master_admin(ctx) else ctx.org.permissions
    perms_dict = {p.uuid: ApiPermission.from_db(p) for p in perms}

    # OIDC Clients (master admin only)
    oidc_clients_dict = {}
    if master_admin(ctx):
        clients = sorted(db.data().oidc.clients.values(), key=lambda c: c.uuid)
        sessions = db.data().sessions
        # Count active sessions per client
        client_session_counts = {}
        for session in sessions.values():
            if session.client_uuid:
                client_session_counts[session.client_uuid] = (
                    client_session_counts.get(session.client_uuid, 0) + 1
                )
        oidc_clients_dict = {
            client.uuid: ApiOidcClient.from_db(
                client, client_session_counts.get(client.uuid, 0)
            )
            for client in clients
        }

    return MsgspecResponse(
        ApiAdminInfo(
            orgs=orgs_dict,
            permissions=perms_dict,
            oidc_clients=oidc_clients_dict,
        )
    )
