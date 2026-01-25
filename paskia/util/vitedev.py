"""Vite dev server proxy for fetching frontend files during development.

In dev mode (FASTAPI_VUE_FRONTEND_URL set), fetches files from Vite.
In production, reads from the static build directory.

This complements fastapi_vue.Frontend which handles static file serving
but doesn't provide server-side fetching of HTML content.
"""

import asyncio
import mimetypes
import os
from pathlib import Path

import httpx

__all__ = ["read"]


def _get_dev_server() -> str | None:
    """Get the dev server URL from environment, or None if not in dev mode."""
    return os.environ.get("FASTAPI_VUE_FRONTEND_URL") or None


def _resolve_static_dir() -> Path:
    """Resolve the static files directory."""
    from importlib import resources

    # Try packaged path via importlib.resources (works for wheel/installed).
    try:  # pragma: no cover - trivial path resolution
        pkg_dir = resources.files("paskia") / "frontend-build"
        fs_path = Path(str(pkg_dir))
        if fs_path.is_dir():
            return fs_path
    except Exception:  # pragma: no cover - defensive
        pass
    # Fallback for editable/development before build.
    return Path(__file__).parent.parent / "frontend-build"


_static_dir: Path = _resolve_static_dir()


async def read(filepath: str) -> tuple[bytes, int, dict[str, str]]:
    """Read file content and return response tuple.

    In dev mode, fetches from the Vite dev server.
    In production, reads from the static build directory.

    Args:
        filepath: Path relative to frontend root, e.g. "/auth/index.html"

    Returns:
        Tuple of (content, status_code, headers) suitable for
        FastAPI Response(*args).
    """
    dev_server = _get_dev_server()
    if dev_server:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{dev_server}{filepath}")
            resp.raise_for_status()
            mime = resp.headers.get("content-type", "application/octet-stream")
            # Strip charset suffix if present
            mime = mime.split(";")[0].strip()
            return resp.content, resp.status_code, {"content-type": mime}
    else:
        # Production: read from static build
        file_path = _static_dir / filepath.lstrip("/")
        content = await asyncio.to_thread(file_path.read_bytes)
        mime, _ = mimetypes.guess_type(str(file_path))
        return content, 200, {"content-type": mime or "application/octet-stream"}
