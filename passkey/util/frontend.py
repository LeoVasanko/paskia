import atexit
import shutil
import signal
import subprocess
from importlib import resources
from pathlib import Path
from sys import stderr
from threading import Thread

__all__ = ["path", "file", "run_dev"]

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
┃ Note: only static build of the frontend is served at port 8078.
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
