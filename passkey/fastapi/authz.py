"""Authorization utilities shared across FastAPI endpoints.

Provides helper(s) to validate a session token (from cookie) and optionally
enforce that the user possesses a given permission (either via their role or
their organization level permissions).
"""

from fastapi import HTTPException

from ..authsession import get_session
from ..globals import db
from ..util.tokens import session_key


async def verify(auth: str | None, perm: str | None):
    """Validate session token and optional permission.

    Returns the Session object on success. Raises HTTPException on failure.
    401: unauthenticated / invalid session
    403: missing required permission
    """
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
    session = await get_session(auth)
    if perm:
        ctx = await db.instance.get_session_context(session_key(auth))
        if not ctx:
            raise HTTPException(status_code=401, detail="Session not found")
        role_perms = set(ctx.role.permissions or [])
        org_perms = set(ctx.org.permissions or []) if ctx.org else set()
        if perm not in role_perms and perm not in org_perms:
            raise HTTPException(status_code=403, detail="Permission required")
    return session


__all__ = ["verify"]
