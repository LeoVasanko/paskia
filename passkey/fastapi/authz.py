from fastapi import HTTPException

from ..util import permutil


async def verify(auth: str | None, perm: list[str], match=permutil.has_all):
    """Validate session token and optional list of required permissions.

    Returns the session context.

    Raises HTTPException on failure:
      401: unauthenticated / invalid session
      403: required permissions missing
    """
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")

    ctx = await permutil.session_context(auth)
    if not ctx:
        raise HTTPException(status_code=401, detail="Session not found")

    if not match(ctx, perm):
        raise HTTPException(status_code=403, detail="Permission required")

    return ctx
