"""User information formatting and retrieval logic."""

from datetime import timezone

from paskia import aaguid, db
from paskia.authsession import EXPIRES
from paskia.db import SessionContext
from paskia.util import hostutil, permutil, useragent


def _format_datetime(dt):
    """Format a datetime object to ISO 8601 string with UTC timezone."""
    if dt is None:
        return None
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    else:
        return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def format_session_context(ctx: SessionContext) -> dict:
    """Format SessionContext for JSON response."""
    return {
        "user": {
            "uuid": str(ctx.user.uuid),
            "display_name": ctx.user.display_name,
        },
        "org": {
            "uuid": str(ctx.org.uuid),
            "display_name": ctx.org.display_name,
        },
        "role": {
            "uuid": str(ctx.role.uuid),
            "display_name": ctx.role.display_name,
        },
        "permissions": [p.scope for p in ctx.permissions],
    }


async def format_user_info(
    *,
    user_uuid,
    auth: str,
    session_record,
    request_host: str | None,
) -> dict:
    """Format complete user information for authenticated users."""
    ctx = await permutil.session_context(auth, request_host)

    # Fetch and format credentials
    user_credentials = db.get_credentials_by_user_uuid(user_uuid)
    credentials: list[dict] = []
    user_aaguids: set[str] = set()

    for c in user_credentials:
        aaguid_str = str(c.aaguid)
        user_aaguids.add(aaguid_str)
        credentials.append(
            {
                "credential_uuid": str(c.uuid),
                "aaguid": aaguid_str,
                "created_at": _format_datetime(c.created_at),
                "last_used": _format_datetime(c.last_used),
                "last_verified": _format_datetime(c.last_verified),
                "sign_count": c.sign_count,
                "is_current_session": session_record.credential_uuid == c.uuid,
            }
        )

    credentials.sort(key=lambda cred: cred["created_at"])
    aaguid_info = aaguid.filter(user_aaguids)

    # Format sessions
    normalized_request_host = hostutil.normalize_host(request_host)
    session_records = db.list_sessions_for_user(user_uuid)
    current_session_key = auth
    sessions_payload: list[dict] = []

    for entry in session_records:
        sessions_payload.append(
            {
                "id": entry.key,
                "credential_uuid": str(entry.credential_uuid),
                "host": entry.host,
                "ip": entry.ip,
                "user_agent": useragent.compact_user_agent(entry.user_agent),
                "last_renewed": _format_datetime(entry.expiry - EXPIRES),
                "is_current": entry.key == current_session_key,
                "is_current_host": bool(
                    normalized_request_host
                    and entry.host
                    and entry.host == normalized_request_host
                ),
            }
        )

    return {
        "ctx": format_session_context(ctx),
        "created_at": _format_datetime(ctx.user.created_at),
        "last_seen": _format_datetime(ctx.user.last_seen),
        "visits": ctx.user.visits,
        "credentials": credentials,
        "aaguid_info": aaguid_info,
        "sessions": sessions_payload,
    }
