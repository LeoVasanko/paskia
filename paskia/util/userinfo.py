"""User information formatting and retrieval logic."""

from paskia import aaguid, db
from paskia.db import SessionContext
from paskia.util import hostutil
from paskia.util.apistructs import (
    ApiAaguidInfo,
    ApiOrg,
    ApiOrgContext,
    ApiPermission,
    ApiRole,
    ApiRoleContext,
    ApiSessionContext,
    ApiUser,
    ApiUserContext,
    ApiUserDetail,
    ApiUserSession,
)


def build_session_context(ctx: SessionContext) -> ApiSessionContext:
    """Build session context struct from SessionContext."""
    user = ApiUserContext(
        uuid=ctx.user.uuid,
        display_name=ctx.user.display_name,
        theme=ctx.user.theme,
    )
    org = ApiOrgContext(uuid=ctx.org.uuid, display_name=ctx.org.display_name)
    role = ApiRoleContext(uuid=ctx.role.uuid, display_name=ctx.role.display_name)
    return ApiSessionContext(
        user=user,
        org=org,
        role=role,
        permissions=[p.scope for p in ctx.permissions],
    )


async def build_user_info(
    *,
    user_uuid,
    session_key: str,
    request_host: str | None,
    ctx: SessionContext | None = None,
) -> ApiUserDetail:
    """Build user info struct for authenticated users."""
    user = db.data().users[user_uuid]
    normalized_host = hostutil.normalize_host(request_host)

    sessions = {
        s.key: ApiUserSession.from_db(
            s,
            current_key=session_key,
            normalized_host=normalized_host,
        )
        for s in user.sessions
    }

    return ApiUserDetail(
        user=ApiUser.from_db(user),
        credentials={c.uuid: c for c in user.credentials},
        aaguid_info={
            k: ApiAaguidInfo(**v)
            for k, v in aaguid.filter(c.aaguid for c in user.credentials).items()
        },
        sessions=sessions,
        permissions={p.uuid: ApiPermission.from_db(p) for p in ctx.permissions}
        if ctx
        else {},
        org=ApiOrg.from_db(ctx.org) if ctx else None,
        role=ApiRole.from_db(ctx.role) if ctx else None,
    )
