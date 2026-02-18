import asyncio
import mimetypes
import os
from importlib import resources
from pathlib import Path

import httpx

__all__ = ["path", "file", "read", "is_dev_mode"]


def _get_dev_server() -> str | None:
    """Get the dev server URL from environment, or None if not in dev mode."""
    return os.environ.get("PASKIA_VITE_URL") or None


def _resolve_static_dir() -> Path:
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


path: Path = _resolve_static_dir()


def file(*parts: str) -> Path:
    """Return a child path under the static root."""
    return path.joinpath(*parts)


def is_dev_mode() -> bool:
    """Check if we're running in dev mode (Vite frontend server)."""
    return bool(_get_dev_server())


async def read(filepath: str) -> tuple[bytes, int, dict[str, str]]:
    """Read file content and return response tuple.

    In dev mode, fetches from the Vite dev server.
    In production, reads from the static build directory.

    Args:
        filepath: Path relative to frontend root, e.g. "/auth/index.html"

    Returns:
        Tuple of (content, status_code, headers) suitable for
        FastAPI Response(*args) or Sanic raw response.
    """
    if is_dev_mode():
        dev_server = _get_dev_server()
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{dev_server}{filepath}")
            resp.raise_for_status()
            mime = resp.headers.get("content-type", "application/octet-stream")
            # Strip charset suffix if present
            mime = mime.split(";")[0].strip()
            return resp.content, resp.status_code, {"content-type": mime}
    else:
        # Production: read from static build
        file_path = path / filepath.lstrip("/")
        content = await _read_file_async(file_path)
        mime, _ = mimetypes.guess_type(str(file_path))
        return content, 200, {"content-type": mime or "application/octet-stream"}


async def _read_file_async(file_path: Path) -> bytes:
    """Read file asynchronously using asyncio.to_thread."""
    return await asyncio.to_thread(file_path.read_bytes)
