#!/usr/bin/env -S uv run
"""Run Vite development server for Vue app and FastAPI backend with auto-reload."""

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlparse

import tracerite

from paskia.db.legacy import find_legacy_databases
from paskia.db.paths import db_file_path

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

DEFAULT_VITE_PORT = 4403
DEFAULT_DEV_PORT = 4402
CADDY_PORT = 443  # HTTPS port for Caddy proxy
CADDY_HTTP_PORT = 80  # HTTP port for ACME challenges

CADDYFILE_SITE_BLOCK = """\
SITE_ADDR {
	# WebSockets bypass directly to backend (workaround for bun proxy bug)
	handle /auth/ws/* {
		reverse_proxy BACKEND_ADDR
	}
	# Everything else goes to or via Vite
	handle {
		reverse_proxy VITE_ADDR
	}
}
"""


def build_caddyfile(origins: list[str], viteurl: str, backurl: str) -> str:
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
            .replace("BACKEND_ADDR", backurl)
            .replace("VITE_ADDR", viteurl)
        )
        caddyfile_parts.append(block)
    return "\n".join(caddyfile_parts)


async def run_caddy(
    origins: list[str], viteurl: str, backurl: str
) -> asyncio.subprocess.Process:
    """Start Caddy as HTTPS reverse proxy, wait for ready signal."""
    caddy_path = shutil.which("caddy")
    if not caddy_path:
        logger.warning("Caddy not found. Install it to use --caddy option.")
        raise SystemExit(1)

    caddyfile = build_caddyfile(origins, viteurl, backurl)
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


def _split_multi(values: list[str] | None) -> list[str]:
    """Split repeatable/comma-separated CLI values into a flat list."""
    result = []
    for value in values or []:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def ensure_database(rp_ids: list[str], args: argparse.Namespace, listen: str) -> None:
    """Bootstrap paskia.kantadb via 'paskia init' when no database exists.

    Domain options are init-only; 'paskia' (serve) reads all configuration
    from the database. A legacy *.paskiadb database must be converted with
    'paskia migrate' first.
    """
    if db_file_path().exists():
        return
    if find_legacy_databases():
        raise SystemExit(
            "Legacy *.paskiadb database found — run 'paskia migrate' to "
            "convert it before starting the dev server."
        )

    for i, rp_id in enumerate(rp_ids):
        cmd = [sys.executable, "-m", "paskia", "init", rp_id]
        if i == 0:
            if args.rp_name:
                cmd.append(args.rp_name)
            cmd.append(f"--listen={listen}")
        logger.info(">>> paskia init %s", rp_id)
        proc = subprocess.run(cmd, check=False)  # noqa: S603
        if proc.returncode != 0:
            raise SystemExit(proc.returncode)


async def run_devserver(args: argparse.Namespace, remaining: list[str]) -> None:
    """Run the development server with all components."""
    reporoot = Path(__file__).parent.parent
    frontend_path = reporoot / "frontend"
    if not (frontend_path / "package.json").exists():
        logger.warning("Frontend source not found at %s", frontend_path)
        raise SystemExit(1)

    viteurl, npm_install, vite = setup_vite(args.listen, DEFAULT_VITE_PORT)
    backurl, paskia = setup_cli("paskia", args.backend, DEFAULT_DEV_PORT)

    rp_ids = _split_multi(args.rp_id) or ["localhost"]
    ensure_database(rp_ids, args, listen=backurl.removeprefix("http://"))

    # Serve: no domain options — all configuration lives in the database
    paskia.extend(remaining)

    # Set environment for subprocesses
    os.environ["PASKIA_VITE_URL"] = viteurl
    os.environ["PASKIA_BACKEND_URL"] = backurl
    os.environ["PASKIA_DEV"] = "1"

    async with ProcessGroup() as pg:
        # Start Caddy first if requested (needs to bind ports)
        if args.caddy:
            caddy_origins = []
            for rp_id in rp_ids:
                caddy_origins.append(f"https://{rp_id}")
            seen: set = set()
            caddy_origins = [x for x in caddy_origins if not (x in seen or seen.add(x))]
            caddy_proc = await run_caddy(caddy_origins, viteurl, backurl)
            pg._procs.append(caddy_proc)
            pg._cmds[caddy_proc.pid] = "caddy"

        npm_proc = await pg.spawn(*npm_install, cwd=frontend_path)
        await check_ports_free(viteurl, backurl)
        await pg.spawn(*paskia)
        await pg.wait(
            npm_proc, ready(backurl, path="/auth/api/settings?from=devserver.py")
        )
        await pg.spawn(*vite, cwd=frontend_path)


def main():
    tracerite.load()
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "-l",
        "--listen",
        metavar="addr",
        help=f"Vite (default: localhost:{DEFAULT_VITE_PORT})",
    )
    parser.add_argument(
        "--backend",
        metavar="addr",
        help=f"FastAPI (default: localhost:{DEFAULT_DEV_PORT})",
    )
    parser.add_argument("--caddy", action="store_true", help="Run Caddy as HTTPS proxy")
    parser.add_argument(
        "--rp-id",
        action="append",
        help="Relying Party ID(s) for first-run bootstrap (default: localhost). "
        "Repeatable and comma-separated.",
    )
    parser.add_argument(
        "--rp-name", help="Relying Party name of the first domain (bootstrap only)"
    )
    args, remaining = parser.parse_known_args()

    with suppress(KeyboardInterrupt):
        asyncio.run(run_devserver(args, remaining))


HELP_EPILOG = """
  Other options are forwarded to paskia [args]

  JS_RUNTIME environment variable can be used to select the JS runtime:
  npm, deno, bun, or full path to the runtime executable (node maps to npm).
"""


if __name__ == "__main__":
    main()
