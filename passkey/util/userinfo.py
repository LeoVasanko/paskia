"""User information formatting and retrieval logic."""

from datetime import timezone

from passkey.util import useragent

from .. import aaguid
from ..authsession import session_key
from ..globals import db
from . import hostutil, permutil, tokens


def _format_datetime(dt):
    """Format a datetime object to ISO 8601 string with UTC timezone."""
    if dt is None:
        return None
    if dt.tzinfo:
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    else:
        return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


async def format_user_info(
    *,
    user_uuid,
    auth: str,
    session_record,
    request_host: str | None,
) -> dict:
    """Format complete user information for authenticated users.

    Args:
        user_uuid: UUID of the user to fetch information for
        auth: Authentication token
        session_record: Current session record
        request_host: Host header from the request

    Returns:
        Dictionary containing formatted user information including:
        - User details
        - Organization and role information
        - Credentials list
        - Sessions list
        - Permissions
    """
    u = await db.instance.get_user_by_uuid(user_uuid)
    ctx = await permutil.session_context(auth, request_host)

    # Fetch and format credentials
    credential_ids = await db.instance.get_credentials_by_user_uuid(user_uuid)
    credentials: list[dict] = []
    user_aaguids: set[str] = set()

    for cred_id in credential_ids:
        try:
            c = await db.instance.get_credential_by_id(cred_id)
        except ValueError:
            continue

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

    # Format role and org information
    role_info = None
    org_info = None
    effective_permissions: list[str] = []
    is_global_admin = False
    is_org_admin = False

    if ctx:
        role_info = {
            "uuid": str(ctx.role.uuid),
            "display_name": ctx.role.display_name,
            "permissions": ctx.role.permissions,
        }
        org_info = {
            "uuid": str(ctx.org.uuid),
            "display_name": ctx.org.display_name,
            "permissions": ctx.org.permissions,
        }
        effective_permissions = [p.id for p in (ctx.permissions or [])]
        is_global_admin = "auth:admin" in (role_info["permissions"] or [])
        is_org_admin = any(
            p.startswith("auth:org:") for p in (role_info["permissions"] or [])
        )

    # Format sessions
    normalized_request_host = hostutil.normalize_host(request_host)
    session_records = await db.instance.list_sessions_for_user(user_uuid)
    current_session_key = session_key(auth)
    sessions_payload: list[dict] = []

    for entry in session_records:
        sessions_payload.append(
            {
                "id": tokens.encode_session_key(entry.key),
                "host": entry.host,
                "ip": entry.ip,
                "user_agent": useragent.compact_user_agent(entry.user_agent),
                "last_renewed": _format_datetime(entry.renewed),
                "is_current": entry.key == current_session_key,
                "is_current_host": bool(
                    normalized_request_host
                    and entry.host
                    and entry.host == normalized_request_host
                ),
            }
        )

    return {
        "authenticated": True,
        "user": {
            "user_uuid": str(u.uuid),
            "user_name": u.display_name,
            "created_at": _format_datetime(u.created_at),
            "last_seen": _format_datetime(u.last_seen),
            "visits": u.visits,
        },
        "org": org_info,
        "role": role_info,
        "permissions": effective_permissions,
        "is_global_admin": is_global_admin,
        "is_org_admin": is_org_admin,
        "credentials": credentials,
        "aaguid_info": aaguid_info,
        "sessions": sessions_payload,
    }


async def format_reset_user_info(user_uuid, reset_token) -> dict:
    """Format minimal user information for reset token requests.

    Args:
        user_uuid: UUID of the user
        reset_token: Reset token record

    Returns:
        Dictionary with minimal user info for password reset flow
    """
    u = await db.instance.get_user_by_uuid(user_uuid)

    return {
        "authenticated": False,
        "session_type": reset_token.token_type,
        "user": {"user_uuid": str(u.uuid), "user_name": u.display_name},
    }
