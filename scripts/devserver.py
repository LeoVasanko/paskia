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

Options:
    --caddy         Run Caddy as HTTPS proxy on port 443 (requires sudo)
    --rp-id HOST    Relying Party ID (used as hostname for Caddy)
    --origin URL    Allowed origin(s), passed to backend
    --auth-host H   Dedicated auth host, passed to backend
"""

import argparse
import atexit
import ipaddress
import json
import os
import shutil
import signal
import subprocess
from pathlib import Path
from sys import stderr
from threading import Thread
from urllib.parse import urlparse

DEFAULT_VITE_PORT = 4403  # overrides by CLI option
BACKEND_PORT = 4402  # hardcoded, also in vite.config.ts
CADDY_PORT = 443  # HTTPS port for Caddy proxy
CADDY_HTTP_PORT = 80  # HTTP port for ACME challenges
DEFAULT_HOST = "localhost"

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

CADDYFILE_SITE_BLOCK = """\
SITE_ADDR {
    # WebSockets bypass directly to backend (workaround for bun proxy bug)
	handle /auth/ws/* {
		reverse_proxy localhost:BACKEND_PORT
	}
	# Everything else goes to or via Vite
	handle {
		reverse_proxy localhost:VITE_PORT
	}
}
"""


def parse_endpoint(
    value: str | None, default_port: int
) -> tuple[str | None, int | None, str | None, bool]:
    """Parse an endpoint for Vite (simplified version for dev.py).

    Returns (host, port, uds_path, all_ifaces).
    """
    if not value:
        return DEFAULT_HOST, default_port, None, False

    # Port only (numeric) -> localhost:port
    if value.isdigit():
        return DEFAULT_HOST, int(value), None, False

    # Leading colon :port -> bind all interfaces
    if value.startswith(":") and value != ":":
        port_part = value[1:]
        if not port_part.isdigit():
            raise SystemExit(f"Invalid port in '{value}'")
        return None, int(port_part), None, True

    # UNIX domain socket
    if value.startswith("unix:"):
        uds_path = value[5:] or None
        if uds_path is None:
            raise SystemExit("unix: path must not be empty")
        return None, None, uds_path, False

    # Unbracketed IPv6 (cannot safely contain a port)
    if value.count(":") > 1 and not value.startswith("["):
        try:
            ipaddress.IPv6Address(value)
        except ValueError as e:
            raise SystemExit(f"Invalid IPv6 address '{value}': {e}")
        return value, default_port, None, False

    # Use urllib.parse for everything else
    parsed = urlparse(f"//{value}")
    host = parsed.hostname or DEFAULT_HOST
    port = parsed.port or default_port

    return host, port, None, False


def run_vite(
    vite_url: str, vite_host: str | None, vite_port: int, auth_host: str | None = None
):
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
        ("npm", "--silent", "run", "dev", "--"),
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
    vite_args = ["--port", str(vite_port), "--logLevel", "silent"]
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
            vite_env = os.environ.copy()
            if auth_host:
                vite_env["PASKIA_AUTH_HOST"] = auth_host
            vite_process = subprocess.Popen(
                full_cmd, cwd=str(devpath), shell=False, env=vite_env
            )
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


def run_caddy(origins: list[str], vite_port: int) -> subprocess.Popen | None:
    """Spawn Caddy as HTTPS reverse proxy for the given origins."""
    caddy_path = shutil.which("caddy")
    if not caddy_path:
        stderr.write("┃ ⚠️  Caddy not found. Install it to use --caddy option.\n")
        return None

    # Build Caddyfile with a site block for each origin
    caddyfile_parts = []
    for origin in origins:
        parsed = urlparse(origin)
        # Extract scheme://host:port from origin URL
        scheme = parsed.scheme or "https"
        host = parsed.hostname or parsed.path  # handle case without scheme
        port = parsed.port or (CADDY_HTTP_PORT if scheme == "http" else CADDY_PORT)
        # Use standard ports without explicit port in address (cleaner URLs)
        if port in (80, 443):
            site_addr = f"{scheme}://{host}"
        else:
            site_addr = f"{scheme}://{host}:{port}"
        block = (
            CADDYFILE_SITE_BLOCK.replace("SITE_ADDR", site_addr)
            .replace("BACKEND_PORT", str(BACKEND_PORT))
            .replace("VITE_PORT", str(vite_port))
        )
        caddyfile_parts.append(block)

    caddyfile = "\n".join(caddyfile_parts)
    caddy_process = None

    try:
        # Use sudo to bind to privileged ports (80/443) for ACME certificate fetching
        cmd = ["sudo", caddy_path, "run", "--config", "-", "--adapter", "caddyfile"]
        caddy_process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        caddy_process.stdin.write(caddyfile.encode())
        caddy_process.stdin.close()
    except Exception as e:
        stderr.write(f"┃ ⚠️  Caddy couldn't start: {e}\n")
        return None

    # Helper to parse Caddy log line (JSON or plain text) into (level, logger, msg)
    def parse_caddy_log(line: str) -> tuple[str, str, str] | None:
        """Parse a Caddy log line, return (level, logger, msg) or None if unparseable."""
        line = line.rstrip("\n")
        if not line:
            return None

        # Try JSON format first
        try:
            log = json.loads(line)
            return (
                log.get("level", ""),
                log.get("logger", ""),
                log.get("msg", ""),
            )
        except json.JSONDecodeError:
            pass

        # Plain text format: "2025/12/06 22:59:41.390 INFO    logger    msg..."
        # or "2025/12/06 22:59:41.390 INFO    msg..." (no logger)
        parts = line.split("\t")
        if len(parts) >= 2:
            # First part is "timestamp LEVEL", rest are logger and/or message
            first = parts[0].rsplit(None, 1)  # split off the level from timestamp
            if len(first) == 2:
                level = first[1].lower()
                if len(parts) == 2:
                    return (level, "", parts[1])
                else:
                    return (level, parts[1], "\t".join(parts[2:]))

        # Unparseable - return as-is with no level/logger
        return ("", "", line)

    def strip_caddy_verbose(msg: str) -> str:
        """Remove verbose prefixes from Caddy error messages."""
        return msg.replace("loading initial config: loading new config: ", "")

    def format_caddy_log(level: str, logger: str, msg: str) -> str:
        """Format a parsed Caddy log for display."""
        msg = strip_caddy_verbose(msg)
        if logger:
            return f"┃ [{level.upper()}] {logger}: {msg}\n"
        else:
            return f"┃ [{level.upper()}] {msg}\n"

    # Read stderr line by line until Caddy signals it's ready or exits
    # Caddy outputs logs; "serving initial configuration" means it's ready
    while True:
        exit_code = caddy_process.poll()
        if exit_code is not None:
            # Process exited - read remaining stderr and report failure
            remaining = (
                caddy_process.stderr.read().decode() if caddy_process.stderr else ""
            )
            if remaining:
                for line in remaining.splitlines():
                    if line:
                        parsed = parse_caddy_log(line)
                        if parsed:
                            level, logger, msg = parsed
                            if level:
                                stderr.write(format_caddy_log(level, logger, msg))
                            else:
                                stderr.write(f"┃ {strip_caddy_verbose(msg)}\n")
                        else:
                            stderr.write(f"┃ {strip_caddy_verbose(line)}\n")
            stderr.write(f"┃ ⚠️  Caddy startup failed (exit code {exit_code})\n")
            return None

        # Read one line from stderr (blocks until data available)
        line = caddy_process.stderr.readline().decode()
        if not line:
            continue

        # Check for ready signal
        if "serving initial configuration" in line:
            break

        parsed = parse_caddy_log(line)
        if not parsed:
            continue

        level, logger, msg = parsed

        # Filter out info-level and admin messages
        if level == "info" or logger == "admin":
            continue

        # Show errors/fatal to user
        if level in ("error", "fatal"):
            stderr.write(format_caddy_log(level, logger, msg))
        elif not level:
            # Unparseable non-empty line (e.g., sudo prompt) - pass through with prefix
            stderr.write(f"┃ {strip_caddy_verbose(msg)}\n")
            stderr.flush()

    # Start a background thread to drain stderr and show errors
    def drain_stderr():
        while True:
            line = caddy_process.stderr.readline().decode()
            if not line:
                break

            parsed = parse_caddy_log(line)
            if not parsed:
                continue

            level, logger, msg = parsed

            # Filter out info-level and admin messages
            if level == "info" or logger == "admin":
                continue

            # Show errors/warnings to user
            if level in ("error", "fatal", "warn"):
                stderr.write(format_caddy_log(level, logger, msg))
            elif not level:
                # Unparseable line - pass through with prefix
                stderr.write(f"┃ {strip_caddy_verbose(msg)}\n")

    drain_thread = Thread(target=drain_stderr, daemon=True)
    drain_thread.start()

    def cleanup():
        if caddy_process:
            caddy_process.terminate()
            caddy_process.wait()

    atexit.register(cleanup)

    return caddy_process


def main():
    # Parse optional hostport argument for Vite frontend
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("hostport", nargs="?", default=None)
    parser.add_argument("--caddy", action="store_true", help="Run Caddy as HTTPS proxy")
    parser.add_argument("--rp-id", default="localhost", help="Relying Party ID")
    parser.add_argument(
        "--origin", action="append", dest="origins", help="Allowed origin(s)"
    )
    parser.add_argument("--auth-host", help="Dedicated auth host")
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

    # Compute origins for Caddy (user-specified or auto-generated)
    caddy_origins = []
    if args.auth_host:
        auth_host = args.auth_host
        if "://" not in auth_host:
            auth_host = f"https://{auth_host}"
        caddy_origins.append(auth_host)
        # Also run on rp-id when auth-host is specified
        caddy_origins.append(f"https://{args.rp_id}")
    if args.origins:
        for origin in args.origins:
            if "://" not in origin:
                origin = f"https://{origin}"
            caddy_origins.append(origin)
    # If neither auth-host nor origins specified, run on rp-id
    if not args.auth_host and not args.origins:
        caddy_origins.append(f"https://{args.rp_id}")

    # Remove duplicates while preserving order
    seen = set()
    caddy_origins = [x for x in caddy_origins if not (x in seen or seen.add(x))]

    # Start Caddy if requested (after computing origins)
    if args.caddy:
        if not caddy_origins:
            caddy_origins = [f"https://{args.rp_id}"]
        stderr.write(f">>> sudo caddy @ {' '.join(caddy_origins)}\n")
        if not run_caddy(caddy_origins, vite_port):
            raise SystemExit(1)

    # Start Vite dev server
    run_vite(vite_url, vite_host, vite_port, args.auth_host)

    # Set dev mode with Vite URL in environment for subprocess
    env = os.environ.copy()
    env["PASKIA_DEVMODE"] = vite_url

    # Build command with origin args
    cmd = ["paskia", "serve", f"localhost:{BACKEND_PORT}"]

    # Pass through rp-id (always pass, has default)
    cmd.extend(["--rp-id", args.rp_id])

    # Pass through auth-host if specified
    if args.auth_host:
        cmd.extend(["--auth-host", args.auth_host])

    # Pass through origins as specified
    if args.origins:
        for origin in args.origins:
            cmd.extend(["--origin", origin])

    # Add remaining args (ones we didn't parse)
    cmd.extend(remaining)

    stderr.write(f">>> (devmode) {' '.join(cmd)}\n")
    subprocess.run(cmd, env=env)


if __name__ == "__main__":
    main()
