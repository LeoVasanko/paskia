"""Middleware for handling auth host redirects."""

from fastapi import Request, Response
from fastapi.responses import RedirectResponse

from passkey.util import hostutil, passphrase


def is_ui_path(path: str) -> bool:
    """Check if the path is a UI endpoint."""
    ui_paths = {
        "/",
        "/admin",
        "/admin/",
        "/auth",
        "/auth/",
        "/auth/admin",
        "/auth/admin/",
    }
    if path in ui_paths:
        return True
    # Treat reset token pages as UI (dynamic). Accept single-segment tokens.
    if path.startswith("/auth/"):
        token = path[6:]
        if token and "/" not in token and passphrase.is_well_formed(token):
            return True
    else:
        token = path[1:]
        if token and "/" not in token and passphrase.is_well_formed(token):
            return True
    return False


def is_restricted_path(path: str) -> bool:
    """Check if the path is restricted (API/admin endpoints)."""
    return path.startswith(("/auth/api/admin/", "/auth/api/user/", "/auth/ws/"))


def should_redirect_to_auth_host(path: str) -> bool:
    """Determine if the request should be redirected to the auth host."""
    if path in {"/", "/auth", "/auth/"}:
        return False
    return is_ui_path(path) or is_restricted_path(path)


def redirect_to_auth_host(request: Request, cfg: str, path: str) -> Response:
    """Create a redirect response to the auth host."""
    if is_restricted_path(path):
        return Response(status_code=404)
    new_path = (
        path[5:] or "/" if is_ui_path(path) and path.startswith("/auth") else path
    )
    return RedirectResponse(f"{request.url.scheme}://{cfg}{new_path}", 307)


def should_redirect_auth_path_to_root(path: str) -> bool:
    """Check if /auth/ UI path should be redirected to root on auth host."""
    if not path.startswith("/auth/"):
        return False
    ui_paths = {"/auth", "/auth/", "/auth/admin", "/auth/admin/"}
    if path in ui_paths:
        return True
    # Check for reset token
    token = path[6:]
    return bool(token and "/" not in token and passphrase.is_well_formed(token))


def redirect_to_root_on_auth_host(request: Request, cur: str, path: str) -> Response:
    """Create a redirect response to root path on the same host."""
    new_path = path[5:] or "/"
    return RedirectResponse(f"{request.url.scheme}://{cur}{new_path}", 307)


async def redirect_middleware(request: Request, call_next):
    """Middleware to handle auth host redirects."""
    cfg = hostutil.configured_auth_host()
    if not cfg:
        return await call_next(request)

    cur = hostutil.normalize_host(request.headers.get("host"))
    if not cur:
        return await call_next(request)

    cfg_normalized = hostutil.normalize_host(cfg)
    on_auth_host = cur == cfg_normalized

    path = request.url.path or "/"

    if not on_auth_host:
        if not should_redirect_to_auth_host(path):
            return await call_next(request)
        return redirect_to_auth_host(request, cfg, path)
    else:
        # On auth host: force UI endpoints at root
        if should_redirect_auth_path_to_root(path):
            return redirect_to_root_on_auth_host(request, cur, path)
        return await call_next(request)
