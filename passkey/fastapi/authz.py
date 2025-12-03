import logging

from fastapi import HTTPException

from ..util import frontend, htmlutil, permutil, sessionutil

logger = logging.getLogger(__name__)


class AuthException(HTTPException):
    """Exception raised during authentication/authorization with metadata for the UI.

    Attributes:
        status_code: HTTP status code (401 for auth, 403 for authz)
        detail: Error message
        mode: UI mode ('login' or 'reauth')
        clear_session: Whether to clear the session cookie (True for invalid sessions)
        metadata: Additional data to pass to the frontend
    """

    def __init__(
        self,
        status_code: int,
        detail: str,
        mode: str,
        clear_session: bool = False,
        **metadata,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.mode = mode
        self.clear_session = clear_session
        self.metadata = metadata


def auth_error_content(exc: AuthException) -> dict:
    """Generate JSON response content for an AuthException.

    Returns a dict with detail, mode, and iframe HTML for srcdoc embedding.
    """
    data_attrs = {"mode": exc.mode, **exc.metadata}
    iframe_html = frontend.file("auth", "restricted", "index.html").read_bytes()
    iframe_html = htmlutil.patch_html_data_attrs(iframe_html, **data_attrs)
    return {
        "detail": exc.detail,
        "auth": {
            "mode": exc.mode,
            "iframe": iframe_html.decode("utf-8"),
            **exc.metadata,
        },
    }


async def verify(
    auth: str | None,
    perm: list[str],
    match=permutil.has_all,
    host: str | None = None,
    max_age: str | None = None,
):
    """Validate session token and optional list of required permissions.

    Returns the session context.

    Raises AuthException on failure with metadata for UI rendering.
    """
    if not auth:
        raise AuthException(
            status_code=401,
            detail="Authentication required",
            mode="login",
        )

    ctx = await permutil.session_context(auth, host)
    if not ctx:
        raise AuthException(
            status_code=401,
            detail="Your session has expired. Please sign in again.",
            mode="login",
            clear_session=True,
        )
    # Check max_age requirement if specified
    if max_age:
        try:
            if not sessionutil.check_session_age(ctx, max_age):
                raise AuthException(
                    status_code=401,
                    detail="Additional authentication required",
                    mode="reauth",
                )
        except ValueError as e:
            # Invalid max_age format - log but don't fail the request
            logger.warning(f"Invalid max_age format '{max_age}': {e}")

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
        raise AuthException(
            status_code=403, mode="forbidden", detail="Permission required"
        )

    return ctx
