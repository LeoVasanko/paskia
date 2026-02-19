"""Vite dev server proxy for fetching frontend files during development.

In dev mode (PASKIA_VITE_URL set), fetches files from Vite.
In production, reads from the static build directory.

This complements fastapi_vue.Frontend which handles static file serving
but doesn't provide server-side fetching of HTML content.
"""

import mimetypes
import os
from importlib import resources
from pathlib import Path

import httpx
from fastapi import Response

__all__ = ["handle"]


def _resolve_static_dir() -> Path:
    # Try packaged path via importlib.resources (works for wheel/installed).
    pkg_dir = resources.files("paskia") / "frontend-build"
    fs_path = Path(str(pkg_dir))
    if fs_path.is_dir():
        return fs_path
    # Fallback for editable/development before build.
    return Path(__file__).parent.parent / "frontend-build"


_static_dir: Path = _resolve_static_dir()


async def handle(request, frontend, filepath: str):
    """Read file content and return Response.

    In dev mode, fetches from the Vite dev server.
    In production, uses frontend.handle.

    Args:
        request: The FastAPI Request object
        frontend: The fastapi_vue.Frontend instance
        filepath: Path relative to frontend root, e.g. "/auth/index.html"

    Returns:
        FastAPI Response object.
    """
    if dev_server := os.environ.get("PASKIA_VITE_URL"):
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{dev_server}{filepath}")
            resp.raise_for_status()
            mime = resp.headers.get("content-type", "application/octet-stream")
            # Strip charset suffix if present
            mime = mime.split(";")[0].strip()
            return Response(resp.content, resp.status_code, {"content-type": mime})

    # Read from frontend cache directly to bypass any compression/processing
    cached_content = getattr(frontend, "_files", {}).get(filepath)
    if cached_content is not None:
        mime, _ = mimetypes.guess_type(filepath)
        return Response(
            cached_content, 200, {"content-type": mime or "application/octet-stream"}
        )

    # Fallback to frontend.handle for cache negotiation
    # Strip accept-encoding to get uncompressed content (needed for HTML patching)
    strip_headers = {b"accept-encoding", b"if-none-match", b"if-modified-since"}
    request.scope["headers"] = [
        (k, v) for k, v in request.scope["headers"] if k.lower() not in strip_headers
    ]
    # Invalidate cached Headers object (it doesn't re-read scope after first access)
    if hasattr(request, "_headers"):
        del request._headers

    return frontend.handle(request, filepath)
