"""Strict sub-application factory: no slash redirects, slash-less mount roots.

Starlette's Mount only matches when the mount point is followed by "/", so a
request to the bare mount point ("/oidc-clients") falls through to the
router, which with redirect_slashes enabled answers a 307 to the slash-ful
URL. That redirect's absolute Location is built from the upstream request
scheme, which breaks behind proxies whose forwarded headers are not trusted
(mixed-content block in the browser). Instead of redirecting, we rewrite a
path that exactly equals a mount point to its slash-ful form before routing,
making the slash-less URL work directly. ``redirect_slashes=False`` keeps
every other path strict.
"""

from fastapi import FastAPI
from starlette.routing import Mount, get_route_path


class _SlashlessMounts:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            router = scope.get("router")
            routes = router.routes if router is not None else scope["app"].routes
            mounts = {r.path for r in routes if isinstance(r, Mount)}
            if get_route_path(scope) in mounts:
                scope = dict(scope, path=scope["path"] + "/")
        await self.app(scope, receive, send)


def strict_app(**kwargs) -> FastAPI:
    app = FastAPI(
        redirect_slashes=False,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        **kwargs,
    )
    app.add_middleware(_SlashlessMounts)
    return app
