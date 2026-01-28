"""Custom access logging middleware for FastAPI/Uvicorn."""

import logging
import sys
import time
from ipaddress import IPv6Address

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("paskia.access")

_RESET = "\033[0m"
_STATUS_INFO = "\033[32m"  # 1xx (green)
_STATUS_OK = "\033[92m"  # 2xx (bright green)
_STATUS_REDIRECT = "\033[32m"  # 3xx (green)
_STATUS_CLIENT_ERR = "\033[0;31m"  # 4xx (red)
_STATUS_SERVER_ERR = "\033[1;31m"  # 5xx (bright red)
_METHOD_READ = "\033[0;34m"  # GET, HEAD, OPTIONS (blue)
_METHOD_WRITE = "\033[1;34m"  # POST, PUT, DELETE, PATCH (bright blue)
_HOST = "\033[1;30m"  # hostname (dark grey)
_PATH = "\033[0m"  # path (default)
_TIMING = "\033[2m"  # timing (dim)
_WS_OPEN = "\033[1;33m"  # WebSocket connect (bright yellow)
_WS_CLOSE = "\033[0;33m"  # WebSocket disconnect (yellow)
_WS_STATUS = "\033[1;30m"  # WebSocket close status (dark grey)


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


def log_ws_open(client: str, host: str, path: str) -> int:
    """Log WebSocket connection open. Returns connection ID for use in close."""
    use_color = sys.stderr.isatty()
    ws_id = _next_ws_id()

    ip = format_client_ip(client).ljust(15)
    id_str = f"{ws_id:02d}".ljust(7)  # Align with method field (7 chars)

    if use_color:
        # 🔌 aligned with status (takes ~2 char width), ID aligned with method
        prefix = f"🔌  {_WS_OPEN}{id_str}{_RESET}"
        host_str = f"{_HOST}{host}{_RESET}"
        path_str = f"{_PATH}{path}{_RESET}"
    else:
        prefix = f"WS+ {id_str}"
        host_str = host
        path_str = path

    logger.info(f"{ip} {prefix} {host_str}{path_str}")
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


def log_ws_close(
    client: str, ws_id: int, close_code: int | None, duration_ms: float
) -> None:
    """Log WebSocket connection close with duration and status."""
    use_color = sys.stderr.isatty()

    ip = format_client_ip(client).ljust(15)
    id_str = f"{ws_id:02d}".ljust(7)  # Align with method field (7 chars)
    timing = f"{duration_ms:.0f}ms"

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

    logger.info(f"{ip} {prefix} {status_str} {timing_str}")


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
