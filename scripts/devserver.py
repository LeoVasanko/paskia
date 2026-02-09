#!/usr/bin/env -S uv run
"""Run Vite development server for frontend and Paskia backend with auto-reload.

This script is only available when running from the git repository source,
not from the installed package. It starts both the Vite frontend dev server
and the Paskia backend with auto-reload enabled.

Usage:
    uv run scripts/devserver.py [-l host:port] [options...]

The optional -l/--listen argument sets where the Vite frontend listens.
All other options are forwarded to `paskia`.
Backend always listens on localhost:4402.

Environment:
    PASKIA_FRONTEND_URL    Set by this script for the backend to know where Vite is.
    PASKIA_BACKEND_URL     Set by this script for Vite to know where to proxy API calls.
    PASKIA_SITE_URL        User-facing URL for reset links (Caddy HTTPS or Vite HTTP).

Options:
    --caddy         Run Caddy as HTTPS proxy on port 443 (requires sudo)
    --rp-id HOST    Relying Party ID (used as hostname for Caddy)
    --origin URL    Allowed origin(s), passed to backend
    --auth-host H   Dedicated auth host, passed to backend
"""

import argparse
import asyncio
import json
import os
import shutil
import sys
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlparse

# Import utilities from scripts/fastapi-vue (not a package, so we adjust sys.path)
sys.path.insert(0, str(Path(__file__).with_name("fastapi-vue")))
from devutil import (  # noqa: E402
    ProcessGroup,
    check_ports_free,
    logger,
    ready,
    setup_cli,
    setup_vite,
)

DEFAULT_VITE_PORT = 4403  # overrides by CLI option
BACKEND_PORT = 4402  # hardcoded, also in vite.config.ts
CADDY_PORT = 443  # HTTPS port for Caddy proxy
CADDY_HTTP_PORT = 80  # HTTP port for ACME challenges

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


def build_caddyfile(origins: list[str], vite_port: int) -> str:
    """Build a Caddyfile for the given origins."""
    caddyfile_parts = []
    for origin in origins:
        parsed = urlparse(origin)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or parsed.path
        port = parsed.port or (CADDY_HTTP_PORT if scheme == "http" else CADDY_PORT)
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
    return "\n".join(caddyfile_parts)


async def run_caddy(origins: list[str], vite_port: int) -> asyncio.subprocess.Process:
    """Start Caddy as HTTPS reverse proxy, wait for ready signal."""
    caddy_path = shutil.which("caddy")
    if not caddy_path:
        logger.warning("Caddy not found. Install it to use --caddy option.")
        raise SystemExit(1)

    caddyfile = build_caddyfile(origins, vite_port)
    cmd = ["sudo", caddy_path, "run", "--config", "-", "--adapter", "caddyfile"]

    logger.info(">>> sudo caddy @ %s", " ".join(origins))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    proc.stdin.write(caddyfile.encode())
    await proc.stdin.drain()
    proc.stdin.close()

    # Wait for ready signal or failure
    while True:
        if proc.returncode is not None:
            remaining = await proc.stderr.read()
            for line in remaining.decode().splitlines():
                if line:
                    logger.info("caddy: %s", line)
            logger.warning("Caddy startup failed (exit code %d)", proc.returncode)
            raise SystemExit(1)

        line = await proc.stderr.readline()
        if not line:
            continue

        decoded = line.decode().rstrip()
        if "serving initial configuration" in decoded:
            break

        # Parse and show errors during startup
        if decoded:
            try:
                log = json.loads(decoded)
                level = log.get("level", "")
                if level in ("error", "fatal", "warn"):
                    logger.warning("caddy: %s", log.get("msg", decoded))
            except json.JSONDecodeError:
                if "error" in decoded.lower() or "fatal" in decoded.lower():
                    logger.warning("caddy: %s", decoded)

    # Start background task to drain stderr
    async def drain_caddy_stderr():
        while True:
            line = await proc.stderr.readline()
            if not line:
                break
            decoded = line.decode().rstrip()
            if decoded:
                try:
                    log = json.loads(decoded)
                    level = log.get("level", "")
                    if level in ("error", "fatal", "warn"):
                        logger.warning("caddy: %s", log.get("msg", decoded))
                except json.JSONDecodeError:
                    pass  # Ignore non-JSON output after startup

    asyncio.create_task(drain_caddy_stderr())
    return proc


async def run_devserver(args: argparse.Namespace, remaining: list[str]) -> None:
    """Run the development server with all components."""
    reporoot = Path(__file__).parent.parent
    frontend_path = reporoot / "frontend"
    if not (frontend_path / "package.json").exists():
        logger.warning("Frontend source not found at %s", frontend_path)
        raise SystemExit(1)

    viteurl, npm_install, vite = setup_vite(args.listen, DEFAULT_VITE_PORT)
    backurl, paskia = setup_cli("paskia", f"localhost:{BACKEND_PORT}", BACKEND_PORT)

    # Extract vite port for Caddy config
    vite_port = int(viteurl.rsplit(":", 1)[1])

    # Build paskia command with options
    paskia.extend(["--rp-id", args.rp_id])
    if args.auth_host:
        paskia.extend(["--auth-host", args.auth_host])
    if args.origins:
        for origin in args.origins:
            paskia.extend(["--origin", origin])
    paskia.extend(remaining)

    # Compute origins for Caddy
    caddy_origins = []
    if args.auth_host:
        auth_host = args.auth_host
        if "://" not in auth_host:
            auth_host = f"https://{auth_host}"
        caddy_origins.append(auth_host)
        caddy_origins.append(f"https://{args.rp_id}")
    if args.origins:
        for origin in args.origins:
            if "://" not in origin:
                origin = f"https://{origin}"
            caddy_origins.append(origin)
    if not args.auth_host and not args.origins:
        caddy_origins.append(f"https://{args.rp_id}")
    # Remove duplicates while preserving order
    seen = set()
    caddy_origins = [x for x in caddy_origins if not (x in seen or seen.add(x))]

    # Set environment for subprocesses
    os.environ["PASKIA_FRONTEND_URL"] = viteurl
    os.environ["PASKIA_BACKEND_URL"] = backurl
    os.environ["PASKIA_SITE_URL"] = caddy_origins[0] if args.caddy else viteurl
    if args.auth_host:
        os.environ["PASKIA_AUTH_HOST"] = args.auth_host

    async with ProcessGroup() as pg:
        # Start Caddy first if requested (needs to bind ports)
        if args.caddy:
            caddy_proc = await run_caddy(caddy_origins, vite_port)
            pg._procs.append(caddy_proc)
            pg._cmds[caddy_proc.pid] = "caddy"

        npm_proc = await pg.spawn(*npm_install, cwd=frontend_path)
        await check_ports_free(viteurl, backurl)
        await pg.spawn(*paskia)
        await pg.wait(npm_proc, ready(backurl, path="/api/health?from=devserver.py"))
        await pg.spawn(*vite, cwd=frontend_path)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-l",
        "--listen",
        metavar="ENDPOINT",
        default=None,
        help="Vite frontend endpoint (default: localhost:4403)",
    )
    parser.add_argument("--caddy", action="store_true", help="Run Caddy as HTTPS proxy")
    parser.add_argument("--rp-id", default="localhost", help="Relying Party ID")
    parser.add_argument(
        "--origin", action="append", dest="origins", help="Allowed origin(s)"
    )
    parser.add_argument("--auth-host", help="Dedicated auth host")
    args, remaining = parser.parse_known_args()

    with suppress(KeyboardInterrupt):
        asyncio.run(run_devserver(args, remaining))


if __name__ == "__main__":
    main()
