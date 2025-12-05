#!/usr/bin/env -S uv run
"""Run Vite development server for frontend and FastAPI backend with auto-reload.

This script is only available when running from the git repository source,
not from the installed package. It starts both the Vite frontend dev server
and the FastAPI backend with auto-reload enabled.

Usage:
    uv run scripts/dev.py [host:port] [options...]

The optional host:port argument sets where the Vite frontend listens.
All other options are forwarded to `paskia serve`.
Backend always listens on localhost:4402.
"""

import argparse
import atexit
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from sys import stderr
from threading import Thread

from paskia.fastapi.__main__ import parse_endpoint

DEFAULT_VITE_PORT = 4403  # overrides by CLI option
BACKEND_PORT = 4402  # hardcoded, also in vite.config.ts

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
┃ The backend will still try reaching Vite at {vite_url}
┃ for various frontend assets, so make sure to start it manually.
"""


def run_vite(vite_url: str, vite_host: str | None, vite_port: int):
    """Spawn the frontend dev server (deno, npm, or bunx) as a background process."""
    devpath = Path(__file__).parent.parent / "frontend"
    if not (devpath / "package.json").exists():
        stderr.write(
            f"┃ ⚠️  Frontend source not found at {devpath}\n"
            + NO_FRONTEND.format(vite_url=vite_url)
        )
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

    # Add Vite CLI args for host/port
    vite_args = ["--port", str(vite_port)]
    if vite_host:
        vite_args.extend(["--host", vite_host])

    vite_process = None

    def start_vite():
        nonlocal vite_process
        if cmd is None:
            stderr.write(NO_FRONTEND_TOOL + NO_FRONTEND.format(vite_url=vite_url))
            return
        assert tool_name is not None
        try:
            if tool_name == "bunx":
                stderr.write(BUN_BUG)

            full_cmd = cmd + vite_args
            stderr.write(f">>> {' '.join([tool_name, *full_cmd[1:]])}\n")
            vite_process = subprocess.Popen(full_cmd, cwd=str(devpath), shell=False)
        except Exception as e:
            stderr.write(
                f"┃ ⚠️  Vite couldn't start: {e}\n"
                + NO_FRONTEND.format(vite_url=vite_url)
            )

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
    # Parse optional hostport argument for Vite frontend
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("hostport", nargs="?", default=None)
    args, remaining = parser.parse_known_args()

    # Parse Vite endpoint
    vite_host, vite_port, vite_uds, all_ifaces = parse_endpoint(
        args.hostport, DEFAULT_VITE_PORT
    )

    if vite_uds:
        raise SystemExit("┃ ⚠️  Unix sockets are not supported for Vite frontend")

    # Handle all-interfaces case (:port syntax)
    # Vite uses 0.0.0.0 to listen on all interfaces (IPv4 only, sufficient for dev)
    if all_ifaces:
        vite_host = "0.0.0.0"

    # Build Vite URL for PASKIA_DEVMODE (always use localhost for URL)
    vite_url = f"http://localhost:{vite_port}"

    # Start Vite dev server
    run_vite(vite_url, vite_host, vite_port)

    # Set dev mode with Vite URL
    os.environ["PASKIA_DEVMODE"] = vite_url

    # Import CLI after environment is set up
    from paskia.fastapi.__main__ import main as cli_main

    # Build argv for the main CLI in Dev mode
    # Backend always listens on localhost only (Vite proxies API requests)
    sys.argv = ["paskia", "serve", f"localhost:{BACKEND_PORT}"] + remaining
    cli_main()


if __name__ == "__main__":
    main()
