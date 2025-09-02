from importlib import resources
from pathlib import Path

__all__ = ["path", "file", "run_dev"]


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
    """Spawn the frontend dev server (bun or npm) as a background process."""
    import atexit
    import shutil
    import signal
    import subprocess

    devpath = Path(__file__).parent.parent.parent / "frontend"
    if not (devpath / "package.json").exists():
        raise RuntimeError(
            "Dev frontend is only available when running from git."
            if "site-packages" in devpath.parts
            else f"Frontend source code not found at {devpath}"
        )
    bun = shutil.which("bun")
    npm = shutil.which("npm") if bun is None else None
    if not bun and not npm:
        raise RuntimeError("Neither bun nor npm found on PATH for dev server")
    cmd: list[str] = [bun, "--bun", "run", "dev"] if bun else [npm, "run", "dev"]  # type: ignore[list-item]
    proc = subprocess.Popen(cmd, cwd=str(devpath))

    def _terminate():
        if proc.poll() is None:
            proc.terminate()

    atexit.register(_terminate)

    def _signal_handler(signum, frame):
        _terminate()
        raise SystemExit(0)

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, _signal_handler)
