import logging

from fastapi import HTTPException

from ..util import permutil

logger = logging.getLogger(__name__)


async def verify(
    auth: str | None,
    perm: list[str],
    match=permutil.has_all,
    host: str | None = None,
):
    """Validate session token and optional list of required permissions.

    Returns the session context.

    Raises HTTPException on failure:
      401: unauthenticated / invalid session
      403: required permissions missing
    """
    if not auth:
        raise HTTPException(status_code=401, detail="Authentication required")

    ctx = await permutil.session_context(auth, host)
    if not ctx:
        raise HTTPException(status_code=401, detail="Session not found")

    if not match(ctx, perm):
        # Determine which permissions are missing for clearer diagnostics
        missing = sorted(set(perm) - set(ctx.role.permissions))
        logger.warning(
            "Permission denied: user=%s role=%s missing=%s required=%s granted=%s",  # noqa: E501
            getattr(ctx.user, "uuid", "?"),
            getattr(ctx.role, "display_name", "?"),
            missing,
            perm,
            ctx.role.permissions,
        )
        raise HTTPException(status_code=403, detail="Permission required")

    return ctx
