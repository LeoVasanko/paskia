"""User information formatting and retrieval logic."""

from paskia import aaguid, db
from paskia.authsession import EXPIRES
from paskia.db import SessionContext
from paskia.util import hostutil, permutil
from paskia.util.apistructs import ApiSession


def build_session_context(ctx: SessionContext) -> dict:
    """Build session context dict from SessionContext."""
    return {
        "user": {"uuid": ctx.user.uuid, "display_name": ctx.user.display_name},
        "org": {"uuid": ctx.org.uuid, "display_name": ctx.org.display_name},
        "role": {"uuid": ctx.role.uuid, "display_name": ctx.role.display_name},
        "permissions": [p.scope for p in ctx.permissions],
    }


async def build_user_info(
    *,
    user_uuid,
    auth: str,
    session_record,
    request_host: str | None,
) -> dict:
    """Build user info dict for authenticated users."""
    ctx = await permutil.session_context(auth, request_host)
    user = db.data().users[user_uuid]
    normalized_host = hostutil.normalize_host(request_host)

    credentials = sorted(user.credentials, key=lambda c: c.created_at)
    return {
        "ctx": build_session_context(ctx),
        "created_at": ctx.user.created_at,
        "last_seen": ctx.user.last_seen,
        "visits": ctx.user.visits,
        "credentials": [
            {
                "credential": c.uuid,
                "aaguid": c.aaguid,
                "created_at": c.created_at,
                "last_used": c.last_used,
                "last_verified": c.last_verified,
                "sign_count": c.sign_count,
                "is_current_session": session_record.credential == c.uuid,
            }
            for c in credentials
        ],
        "aaguid_info": aaguid.filter(c.aaguid for c in credentials),
        "sessions": [
            ApiSession.from_db(
                s,
                current_key=auth,
                normalized_host=normalized_host,
                expires_delta=EXPIRES,
            )
            for s in user.sessions
        ],
    }
