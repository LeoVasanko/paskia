"""Custom access logging middleware for FastAPI/Uvicorn."""

import logging
import sys
import time
from ipaddress import IPv6Address
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from paskia.db.structs import SessionContext
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("paskia.access")

_RESET = "\033[0m"
_STATUS_INFO = "\033[32m"  # 1xx (green)
_STATUS_OK = "\033[1;92m"  # 2xx (bright green)
_STATUS_REDIRECT = "\033[32m"  # 3xx (green)
_STATUS_CLIENT_ERR = "\033[0;31m"  # 4xx (red)
_STATUS_SERVER_ERR = "\033[1;91m"  # 5xx (bold bright red)
_METHOD_READ = "\033[0;34m"  # GET, HEAD, OPTIONS (blue)
_METHOD_WRITE = "\033[1;94m"  # POST, PUT, DELETE, PATCH (bold bright blue)
_HOST = "\033[38;5;242m"  # hostname (dark grey)
_PATH = "\033[38;5;250m"  # path (white)
_TIMING = "\033[38;5;242m"  # timing/devmode (dark grey)
_WS_OPEN = "\033[1;93m"  # WebSocket connect (bold bright yellow)
_WS_CLOSE = "\033[33m"  # WebSocket disconnect (yellow)
_WS_STATUS = "\033[38;5;242m"  # WebSocket close status (dark grey)
_AUTHZ_DENIED = "\033[0;31m"  # Permission denied (red)
_AUTHZ_USER = "\033[1;34m"  # User info (light blue)
_AUTHZ_ORG = "\033[34m"  # User info (blue)
_AUTHZ_NEEDS = "\033[1;38;5;231m"  # Needs (brightest white)
_AUTHZ_MISSING = "\033[1;31m"  # Missing scope (bold red)
_AUTHZ_GRANTED = "\033[0;32m"  # Granted scope (green)


def format_ipv6_network(ip: str) -> str:
    """Format IPv6 address to show only network part (first 64 bits)."""
    try:
        addr = IPv6Address(ip)
        # Get the integer representation and mask to first 64 bits
        network_int = int(addr) >> 64
        # Format as IPv6 with trailing ::
        # Split into 4 groups of 16 bits
        groups = []
        for _ in range(4):
            groups.insert(0, format(network_int & 0xFFFF, "x"))
            network_int >>= 16
        # Compress consecutive zero groups
        result = ":".join(groups) + "::"
        # Simplify leading zeros in groups and compress
        return str(IPv6Address(result + "0"))
    except Exception:
        return ip


def format_client_ip(ip: str) -> str:
    """Format client IP, compressing IPv6 to network part only."""
    if not ip or ip == "-":
        return "-"
    if ":" in ip:
        return format_ipv6_network(ip)
    return ip


def status_color(status: int) -> str:
    """Return color code based on HTTP status."""
    if status < 200:
        return _STATUS_INFO
    if status < 300:
        return _STATUS_OK
    if status < 400:
        return _STATUS_REDIRECT
    if status < 500:
        return _STATUS_CLIENT_ERR
    return _STATUS_SERVER_ERR


def method_color(method: str) -> str:
    """Return color code based on HTTP method."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return _METHOD_READ
    return _METHOD_WRITE


def format_access_log(
    client: str, status: int, method: str, host: str, path: str, duration_ms: float
) -> str:
    """Format access log line with colors and aligned fields."""
    use_color = sys.stderr.isatty()

    # Format components with fixed widths for alignment
    ip = format_client_ip(client).ljust(15)  # IPv4 max 15 chars
    timing = f"{duration_ms:.0f}ms"
    method_padded = method.ljust(7)  # Longest method is OPTIONS (7)

    if use_color:
        status_str = f"{status_color(status)}{status}{_RESET}"
        timing_str = f"{_TIMING}{timing}{_RESET}"
        method_str = f"{method_color(method)}{method_padded}{_RESET}"
        host_str = f"{_HOST}{host}{_RESET}"
        path_str = f"{_PATH}{path}{_RESET}"
    else:
        status_str = str(status)
        timing_str = timing
        method_str = method_padded
        host_str = host
        path_str = path

    # Format: "IP STATUS METHOD host path TIMING"
    return f"{ip} {status_str} {method_str} {host_str}{path_str} {timing_str}"


# WebSocket connection counter (mod 100)
_ws_counter = 0


def _next_ws_id() -> int:
    """Get next WebSocket connection ID (0-99)."""
    global _ws_counter
    ws_id = _ws_counter
    _ws_counter = (_ws_counter + 1) % 100
    return ws_id


def log_ws_open(ws) -> int:
    """Log WebSocket connection open. Returns connection ID for use in close."""
    use_color = sys.stderr.isatty()
    ws_id = _next_ws_id()

    client = ws.client.host if ws.client else "-"
    host = ws.headers.get("host", "-")
    path = ws.url.path
    origin = ws.headers.get("origin")

    ip = format_client_ip(client).ljust(15)
    id_str = f"{ws_id:02d}".ljust(7)  # Align with method field (7 chars)

    # Determine if origin should be shown (omit when same as host)
    # Origin header includes scheme (e.g., "https://example.com"), compare host part
    origin_host = origin.split("://", 1)[-1] if origin else None
    show_origin = origin_host and origin_host != host

    if use_color:
        # 🔌 aligned with status (takes ~2 char width), ID aligned with method
        prefix = f"🔌  {_WS_OPEN}{id_str}{_RESET}"
        host_str = f"{_HOST}{host}{_RESET}"
        path_str = f"{_PATH}{path}{_RESET}"
        origin_str = (
            f" {_RESET}from {_HOST}{origin_host}{_RESET}" if show_origin else ""
        )
    else:
        prefix = f"WS+ {id_str}"
        host_str = host
        path_str = path
        origin_str = f" from {origin_host}" if show_origin else ""

    logger.info(f"{ip} {prefix} {host_str}{path_str}{origin_str}")
    return ws_id


# WebSocket close codes to human-readable status
WS_CLOSE_CODES = {
    1000: "ok",
    1001: "going away",
    1002: "protocol error",
    1003: "unsupported",
    1005: "no status",
    1006: "abnormal",
    1007: "invalid data",
    1008: "policy violation",
    1009: "too large",
    1010: "extension required",
    1011: "server error",
    1012: "restarting",
    1013: "try again",
    1014: "bad gateway",
    1015: "tls error",
}


def log_ws_close(ws_id: int, close_code: int | None, duration: float) -> None:
    """Log WebSocket connection close with duration and status."""
    use_color = sys.stderr.isatty()

    id_str = f"{ws_id:02d}".ljust(7)  # Align with method field (7 chars)
    timing = f"{duration * 1000:.0f}ms"

    # Convert close code to status text
    if close_code is None:
        status = "closed"
    else:
        status = WS_CLOSE_CODES.get(close_code, f"code {close_code}")

    if use_color:
        # 🔌 aligned with status, ID aligned with method
        prefix = f"🔌  {_WS_CLOSE}{id_str}{_RESET}"
        status_str = f"{_WS_STATUS}{status}{_RESET}"
        timing_str = f"{_TIMING}{timing}{_RESET}"
    else:
        prefix = f"WS- {id_str}"
        status_str = status
        timing_str = timing

    logger.info(f"{' ' * 15} {prefix} {status_str} {timing_str}")


def log_permission_denied(
    ctx: "SessionContext", required: list[str], missing: list[str], *, require_all: bool
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


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Middleware that logs HTTP requests with custom format."""

    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000

        client = request.client.host if request.client else "-"
        host = request.headers.get("host", "-")
        method = request.method
        path = request.url.path
        if request.url.query:
            path = f"{path}?{request.url.query}"
        status = response.status_code

        line = format_access_log(client, status, method, host, path, duration_ms)
        logger.info(line)

        return response


def configure_access_logging():
    """Configure the access logger to output to stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    # Suppress watchfiles "X changes detected" INFO messages (keep WARNING for reload notification)
    logging.getLogger("watchfiles.main").setLevel(logging.WARNING)
