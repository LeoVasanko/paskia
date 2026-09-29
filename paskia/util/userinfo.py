"""User information formatting and retrieval logic."""

from paskia import aaguid, satellite
from paskia.db import SessionContext
from paskia.util import avatar, hostutil
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
    data = satellite.store_for_host(request_host)
    user = data.users[user_uuid]
    normalized_host = hostutil.normalize_host(request_host)

    user_sessions = [s for s in data.sessions.values() if s.user_uuid == user_uuid]
    user_credentials = [
        c for c in data.credentials.values() if c.user_uuid == user_uuid
    ]

    sessions = {
        s.key: ApiUserSession.from_db(
            s,
            current_key=session_key,
            normalized_host=normalized_host,
        )
        for s in user_sessions
    }

    return ApiUserDetail(
        user=ApiUser.from_db(user, avatar_url=avatar.avatar_browser_url(user.uuid)),
        credentials={c.uuid: c for c in user_credentials},
        aaguid_info={
            k: ApiAaguidInfo(**v)
            for k, v in aaguid.filter(c.aaguid for c in user_credentials).items()
        },
        sessions=sessions,
        permissions={p.uuid: ApiPermission.from_db(p) for p in ctx.permissions}
        if ctx
        else {},
        org=ApiOrg.from_db(ctx.org) if ctx else None,
        role=ApiRole.from_db(ctx.role) if ctx else None,
    )
