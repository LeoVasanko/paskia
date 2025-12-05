#!/usr/bin/env python3
"""Development server script for Paskia.

This script is only available when running from the git repository source,
not from the installed package. It starts both the Vite frontend dev server
and the FastAPI backend with auto-reload enabled.

Usage:
    python scripts/dev.py [options...]

All options are forwarded to `paskia serve`.
"""

import atexit
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from sys import stderr
from threading import Thread

# Set dev mode environment variable BEFORE importing anything from paskia
os.environ["PASKIA_DEVMODE"] = "1"

# Ensure the package is importable when running from repo root
sys.path.insert(0, str(Path(__file__).parent.parent))

DEFAULT_DEV_PORT = 4402
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


def run_vite():
    """Spawn the frontend dev server (deno, npm, or bunx) as a background process."""
    devpath = Path(__file__).parent.parent / "frontend"
    if not (devpath / "package.json").exists():
        stderr.write(f"┃ ⚠️  Frontend source not found at {devpath}\n")
        stderr.write(NO_FRONTEND)
        return

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
        if vite_process:
            vite_process.terminate()
            vite_process.wait()

    # Start Vite in a separate thread
    vite_thread = Thread(target=start_vite, daemon=True)
    vite_thread.start()

    atexit.register(cleanup)
    signal.signal(signal.SIGTERM, lambda *_: cleanup())
    signal.signal(signal.SIGINT, lambda *_: cleanup())


def main():
    # Start Vite dev server first
    run_vite()

    # Set default origin for Vite if not specified
    if "--origin" not in sys.argv:
        os.environ.setdefault("PASKIA_ORIGIN", DEV_SERVER)

    # Build argv for the main CLI
    # Dev mode always listens on localhost:4402 (security: prevents public exposure)
    # User args come after, allowing overrides of other options
    sys.argv = ["paskia", "serve", f"localhost:{DEFAULT_DEV_PORT}"] + sys.argv[1:]

    from paskia.fastapi.__main__ import main as cli_main

    cli_main()


if __name__ == "__main__":
    main()
