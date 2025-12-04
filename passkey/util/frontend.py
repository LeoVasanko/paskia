import asyncio
import atexit
import mimetypes
import os
import shutil
import signal
import subprocess
from importlib import resources
from pathlib import Path
from sys import stderr
from threading import Thread

import httpx

__all__ = ["path", "file", "read", "run_dev"]

DEV_SERVER = "http://localhost:4403"

NO_FRONTEND_TOOL = """\
┃ ⚠️  deno, npm or bunx needed to run the frontend server.
"""

BUN_BUG = """\
┃ ⚠️  Bun cannot correctly proxy API requests to the backend.
┃ Bug report: https://github.com/oven-sh/bun/issues/9882
┃
┃ Options:
┃   - sudo caddy run --config caddy/Caddyfile.dev
┃   - Install deno or npm instead
┃
┃ Caddy will skip the Vite for API calls and serve everything at port 443.
┃ Otherwise Vite serves at port 8077 and proxies to backend (broken with bun).
"""

NO_FRONTEND = """\
┃
┃ Note: only static build of the frontend is served at localhost:4402.
┃ The page will not update with frontend code changes.
"""


def _resolve_static_dir() -> Path:
    # Try packaged path via importlib.resources (works for wheel/installed).
    try:  # pragma: no cover - trivial path resolution
        pkg_dir = resources.files("passkey") / "frontend-build"
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


def _is_dev_mode() -> bool:
    """Check if we're running in dev mode (Vite frontend server)."""
    return os.environ.get("PASSKEY_DEVMODE") == "1"


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
    if _is_dev_mode():
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{DEV_SERVER}{filepath}")
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


def run_dev():
    """Spawn the frontend dev server (deno, npm, or bunx) as a background process."""
    devpath = Path(__file__).parent.parent.parent / "frontend"
    if not (devpath / "package.json").exists():
        raise RuntimeError(
            "Dev frontend is only available when running from git."
            if "site-packages" in devpath.parts
            else f"Frontend source code not found at {devpath}"
        )

    options = [
        ("deno", "run", "dev"),
        ("npm", "run", "dev", "--"),
        ("bunx", "--bun", "vite"),
    ]
    cmd = None
    tool_name = None
    for option in options:
        if tool := shutil.which(option[0]):
            cmd = [tool, *option[1:]]
            tool_name = option[0]
            break

    vite_process = None

    def start_vite():
        nonlocal vite_process
        if cmd is None:
            stderr.write(NO_FRONTEND_TOOL)
            stderr.write(NO_FRONTEND)
            return
        assert tool_name is not None
        try:
            if tool_name == "bunx":
                stderr.write(BUN_BUG)

            stderr.write(f">>> {' '.join([tool_name, *cmd[1:]])}\n")
            vite_process = subprocess.Popen(cmd, cwd=str(devpath), shell=False)
        except Exception as e:
            stderr.write(f"┃ ⚠️  Vite couldn't start: {e}\n")
            stderr.write(NO_FRONTEND)

    def cleanup():
        vite_process.terminate()
        vite_process.wait()

    # Start Vite in a separate thread
    vite_thread = Thread(target=start_vite, daemon=True)
    vite_thread.start()

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: cleanup())
    signal.signal(signal.SIGINT, lambda *_: cleanup())
