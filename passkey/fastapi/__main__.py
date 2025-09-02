import argparse
import asyncio
import atexit
import contextlib
import ipaddress
import logging
import os
import signal
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import uvicorn

DEFAULT_HOST = "localhost"
DEFAULT_SERVE_PORT = 4401
DEFAULT_DEV_PORT = 4402


def parse_endpoint(
    value: str | None, default_port: int
) -> tuple[str | None, int | None, str | None, bool]:
    """Parse an endpoint using stdlib (urllib.parse, ipaddress).

    Returns (host, port, uds_path). If uds_path is not None, host/port are None.

    Supported forms:
    - host[:port]
    - :port (uses default host)
    - [ipv6][:port] (bracketed for port usage)
    - ipv6 (unbracketed, no port allowed -> default port)
    - unix:/path/to/socket.sock
    - None -> defaults (localhost:4401)

    Notes:
    - For IPv6 with an explicit port you MUST use brackets (e.g. [::1]:8080)
    - Unbracketed IPv6 like ::1 implies the default port.
    """
    if not value:
        return DEFAULT_HOST, default_port, None, False

    # Port only (numeric) -> localhost:port
    if value.isdigit():
        try:
            port_only = int(value)
        except ValueError:  # pragma: no cover (isdigit guards)
            raise SystemExit(f"Invalid port '{value}'")
        return DEFAULT_HOST, port_only, None, False

    # Leading colon :port -> bind all interfaces (0.0.0.0 + ::)
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

    # Unbracketed IPv6 (cannot safely contain a port) -> detect by multiple colons
    if value.count(":") > 1 and not value.startswith("["):
        try:
            ipaddress.IPv6Address(value)
        except ValueError as e:  # pragma: no cover
            raise SystemExit(f"Invalid IPv6 address '{value}': {e}")
        return value, default_port, None, False

    # Use urllib.parse for everything else (host[:port], :port, [ipv6][:port])
    parsed = urlparse(f"//{value}")  # // prefix lets urlparse treat it as netloc
    host = parsed.hostname
    port = parsed.port

    # Host may be None if empty (e.g. ':5500')
    if not host:
        host = DEFAULT_HOST
    if port is None:
        port = default_port

    # Validate IP literals (optional; hostname passes through)
    try:
        # Strip brackets if somehow present (urlparse removes them already)
        ipaddress.ip_address(host)
    except ValueError:
        # Not an IP address -> treat as hostname; no action
        pass

    return host, port, None, False


def add_common_options(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--rp-id", default="localhost", help="Relying Party ID (default: localhost)"
    )
    p.add_argument("--rp-name", help="Relying Party name (default: same as rp-id)")
    p.add_argument("--origin", help="Origin URL (default: https://<rp-id>)")


def main():
    # Configure logging to remove the "ERROR:root:" prefix
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

    parser = argparse.ArgumentParser(
        prog="passkey-auth", description="Passkey authentication server"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # serve subcommand
    serve = sub.add_parser(
        "serve", help="Run the server (production style, no auto-reload)"
    )
    serve.add_argument(
        "hostport",
        nargs="?",
        help=(
            "Endpoint (default: localhost:4401). Forms: host[:port] | :port | "
            "[ipv6][:port] | ipv6 | unix:/path.sock"
        ),
    )
    add_common_options(serve)

    # dev subcommand
    dev = sub.add_parser("dev", help="Run the server in development (auto-reload)")
    dev.add_argument(
        "hostport",
        nargs="?",
        help=(
            "Endpoint (default: localhost:4402). Forms: host[:port] | :port | "
            "[ipv6][:port] | ipv6 | unix:/path.sock"
        ),
    )
    add_common_options(dev)

    args = parser.parse_args()

    default_port = DEFAULT_DEV_PORT if args.command == "dev" else DEFAULT_SERVE_PORT
    host, port, uds, all_ifaces = parse_endpoint(args.hostport, default_port)
    devmode = args.command == "dev"

    # Determine origin (dev mode default override)
    origin = args.origin
    if devmode and not args.origin and not args.rp_id:
        # Dev mode: Vite runs on another port, override:
        origin = "http://localhost:4403"

    # Export configuration via environment for lifespan initialization in each process
    os.environ.setdefault("PASSKEY_RP_ID", args.rp_id)
    if args.rp_name:
        os.environ["PASSKEY_RP_NAME"] = args.rp_name
    if origin:
        os.environ["PASSKEY_ORIGIN"] = origin

    # One-time initialization + bootstrap before starting any server processes.
    # Lifespan in worker processes will call globals.init with bootstrap disabled.
    from passkey import globals as _globals  # local import

    asyncio.run(
        _globals.init(
            rp_id=args.rp_id,
            rp_name=args.rp_name,
            origin=origin,
            default_admin=os.getenv("PASSKEY_DEFAULT_ADMIN") or None,
            default_org=os.getenv("PASSKEY_DEFAULT_ORG") or None,
            bootstrap=True,
        )
    )

    run_kwargs: dict = {
        "reload": devmode,
        "log_level": "info",
    }
    if uds:
        run_kwargs["uds"] = uds
    else:
        # For :port form (all interfaces) we will handle separately
        if not all_ifaces:
            run_kwargs["host"] = host
            run_kwargs["port"] = port

    bun_process: subprocess.Popen | None = None
    if devmode:
        # Spawn frontend dev server (bun) only in the original parent (avoid duplicates on reload)
        if os.environ.get("PASSKEY_BUN_PARENT") != "1":
            os.environ["PASSKEY_BUN_PARENT"] = "1"
            frontend_dir = Path(__file__).parent.parent.parent / "frontend"
            if (frontend_dir / "package.json").exists():
                try:
                    bun_process = subprocess.Popen(
                        ["bun", "--bun", "run", "dev"], cwd=str(frontend_dir)
                    )
                    logging.info("Started bun dev server")
                except FileNotFoundError:
                    logging.warning(
                        "bun not found: skipping frontend dev server (install bun)"
                    )

            def _terminate_bun():  # pragma: no cover
                if bun_process and bun_process.poll() is None:
                    with contextlib.suppress(Exception):
                        bun_process.terminate()

            atexit.register(_terminate_bun)

            def _signal_handler(signum, frame):  # pragma: no cover
                _terminate_bun()
                raise SystemExit(0)

            signal.signal(signal.SIGINT, _signal_handler)
            signal.signal(signal.SIGTERM, _signal_handler)

    if all_ifaces and not uds:
        # If reload enabled, fallback to single dual-stack attempt (::) to keep reload simple
        if devmode:
            run_kwargs["host"] = "::"
            run_kwargs["port"] = port
            uvicorn.run("passkey.fastapi:app", **run_kwargs)
        else:
            # Start two servers concurrently: IPv4 and IPv6
            from uvicorn import Config, Server  # noqa: E402 local import

            from passkey.fastapi import app as fastapi_app  # noqa: E402 local import

            async def serve_both():
                servers = []
                assert port is not None
                for h in ("0.0.0.0", "::"):
                    try:
                        cfg = Config(
                            app=fastapi_app,
                            host=h,
                            port=port,
                            log_level="info",
                        )
                        servers.append(Server(cfg))
                    except Exception as e:  # pragma: no cover
                        logging.warning(f"Failed to configure server for {h}: {e}")
                tasks = [asyncio.create_task(s.serve()) for s in servers]
                await asyncio.gather(*tasks)

            asyncio.run(serve_both())
    else:
        uvicorn.run("passkey.fastapi:app", **run_kwargs)


if __name__ == "__main__":
    main()
