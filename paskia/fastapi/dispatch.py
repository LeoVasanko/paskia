"""ASGI dispatch middleware: resolve the request Host to a domain.

Every HTTP request and WebSocket connection is dispatched to exactly one
domain, resolved from the Host header via the domain registry. The resolved
domain is exposed as ``request.state.domain`` and through the
:func:`paskia.domains.current_domain` contextvar, which endpoint code uses
for all domain-dependent behavior (passkey configuration, site URLs).

Unknown hosts are rejected before routing:

- HTTP: ``421 Misdirected Request``
- WebSocket: closed pre-accept with code 1008

For WebSocket connections the Origin header selects the domain when it
belongs to a different domain than the Host — a related-origin page using
the domain's auth host. A cross-domain connection is only allowed when
the Host is the origin domain's own auth host; otherwise the connection
is closed pre-accept. When the Origin is missing or unknown the Host
domain applies and endpoint-side origin validation decides.
"""

from fastapi.responses import PlainTextResponse

from paskia import domains
from paskia.util import hostutil

_WS_CLOSE_POLICY_VIOLATION = 1008


def _header(scope: dict, name: str) -> str | None:
    """Return the first value of a lowercased ASGI header name."""
    key = name.encode()
    for header, value in scope.get("headers", []):
        if header == key:
            return value.decode()
    return None


class DispatchMiddleware:
    """Pure ASGI middleware dispatching each connection to its domain."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            await self._http(scope, receive, send)
        elif scope["type"] == "websocket":
            await self._websocket(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    async def _http(self, scope, receive, send):
        domain = domains.registry().resolve(_header(scope, "host"))
        if domain is None:
            response = PlainTextResponse("Unknown host", status_code=421)
            await response(scope, receive, send)
            return
        await self._dispatch(scope, receive, send, domain)

    async def _websocket(self, scope, receive, send):
        registry = domains.registry()
        host = _header(scope, "host")
        host_domain = registry.resolve(host)
        if host_domain is None:
            # The sync endpoint is server-to-server and token-gated: the
            # satellite may reach us via an address outside our domains.
            if scope.get("path") == "/auth/api/sync/ws" and registry.domains:
                await self._dispatch(scope, receive, send, registry.domains[0])
                return
            await send({"type": "websocket.close", "code": _WS_CLOSE_POLICY_VIOLATION})
            return

        domain = host_domain
        origin = _header(scope, "origin")
        origin_host = hostutil.origin_hostname(origin) if origin else None
        origin_domain = registry.resolve(origin_host) if origin_host else None
        if origin_domain is not None and origin_domain is not host_domain:
            # Cross-domain connection: only via the origin domain's own auth host.
            own = origin_domain.own_auth_host
            if not own or hostutil.normalize_host(host) != hostutil.normalize_host(own):
                await send(
                    {"type": "websocket.close", "code": _WS_CLOSE_POLICY_VIOLATION}
                )
                return
            domain = origin_domain
        await self._dispatch(scope, receive, send, domain)

    async def _dispatch(self, scope, receive, send, domain: domains.Domain):
        scope.setdefault("state", {})["domain"] = domain
        token = domains.set_current_domain(domain)
        try:
            await self.app(scope, receive, send)
        finally:
            domains.reset_current_domain(token)
