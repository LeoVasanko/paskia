"""Authorization-related logging.

HTTP/WebSocket access logging is handled by fastapi_vue's ASGI middleware
(installed via fastapi_vue.server.run); request handlers can pass extra
details to the access log line via request.state.log_extra.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from paskia.db.structs import SessionContext

logger = logging.getLogger("paskia.access")

_RESET = "\033[0m"
_AUTHZ_DENIED = "\033[0;31m"  # Permission denied (red)
_AUTHZ_USER = "\033[1;34m"  # User info (light blue)
_AUTHZ_ORG = "\033[34m"  # User info (blue)
_AUTHZ_NEEDS = "\033[1;38;5;231m"  # Needs (brightest white)
_AUTHZ_MISSING = "\033[1;31m"  # Missing scope (bold red)
_AUTHZ_GRANTED = "\033[0;32m"  # Granted scope (green)


def log_permission_denied(
    ctx: SessionContext, required: list[str], missing: list[str], *, require_all: bool
) -> None:
    """Log permission denied with org, role, user and highlighted missing scopes."""
    missing_set = set(missing)
    scopes = " ".join(
        f"{_AUTHZ_MISSING}{s}✗{_RESET}"
        if s in missing_set
        else f"{_AUTHZ_GRANTED}{s}✓{_RESET}"
        for s in required
    )
    n = "" if len(required) == 1 else " all" if require_all else " any"
    logger.warning(
        f"{_AUTHZ_DENIED}Permission denied{_RESET} "
        f"{_AUTHZ_USER}{ctx.user.display_name}{_RESET} "
        f"{_AUTHZ_ORG}({ctx.org.display_name} {ctx.role.display_name}){_RESET} "
        f"{_AUTHZ_NEEDS}needs{n}:{_RESET} {scopes}"
    )
