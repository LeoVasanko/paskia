"""Authorization utilities shared across FastAPI endpoints.

Provides helper(s) to validate a session token (from cookie) and optionally
enforce that the user possesses a given permission (either via their role or
their organization level permissions).
"""

from fastapi import HTTPException

from ..authsession import get_session
from ..globals import db
from ..util.tokens import session_key


async def verify(auth: str | None, perms: list[str] | None):
    """Validate session token and optional list of required permissions.

    Returns the Session object on success. Raises HTTPException on failure.
    401: unauthenticated / invalid session
    403: one or more required permissions missing
    """
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")
    session = await get_session(auth)
    if perms:
        ctx = await db.instance.get_session_context(session_key(auth))
        if not ctx:
            raise HTTPException(status_code=401, detail="Session not found")
        available = set(ctx.role.permissions or []) | (
            set(ctx.org.permissions or []) if ctx.org else set()
        )
        if any(p not in available for p in perms):
            raise HTTPException(status_code=403, detail="Permission required")
    return session


__all__ = ["verify"]
