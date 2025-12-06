import argparse
import asyncio
import ipaddress
import logging
import os
from urllib.parse import urlparse

import uvicorn

DEFAULT_HOST = "localhost"
DEFAULT_SERVE_PORT = 4401


def is_subdomain(sub: str, domain: str) -> bool:
    """Check if sub is a subdomain of domain (or equal)."""
    sub_parts = sub.lower().split(".")
    domain_parts = domain.lower().split(".")
    if len(sub_parts) < len(domain_parts):
        return False
    return sub_parts[-len(domain_parts) :] == domain_parts


def validate_auth_host(auth_host: str, rp_id: str) -> None:
    """Validate that auth_host is a subdomain of rp_id."""
    parsed = urlparse(auth_host if "://" in auth_host else f"//{auth_host}")
    host = parsed.hostname or parsed.path
    if not host:
        raise SystemExit(f"Invalid auth-host: '{auth_host}'")
    if not is_subdomain(host, rp_id):
        raise SystemExit(
            f"auth-host '{auth_host}' is not a subdomain of rp-id '{rp_id}'"
        )


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
    p.add_argument(
        "--origin",
        action="append",
        dest="origins",
        metavar="URL",
        help="Allowed origin URL(s). May be specified multiple times. If any are specified, only those origins are permitted for WebSocket authentication.",
    )
    p.add_argument(
        "--auth-host",
        help=(
            "Dedicated host (optionally with scheme/port) to serve the auth UI at the root,"
            " e.g. auth.example.com or https://auth.example.com"
        ),
    )


def main():
    # Configure logging to remove the "ERROR:root:" prefix
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

    parser = argparse.ArgumentParser(
        prog="paskia", description="Paskia authentication server"
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

    # reset subcommand
    reset = sub.add_parser(
        "reset",
        help=(
            "Create a credential reset link for a user. Provide part of the display name or UUID. "
            "If omitted, targets the master admin (first Administration role user in an auth:admin org)."
        ),
    )
    reset.add_argument(
        "query",
        nargs="?",
        help="User UUID (full) or case-insensitive substring of display name. If omitted, master admin is used.",
    )
    add_common_options(reset)

    args = parser.parse_args()

    if args.command == "serve":
        host, port, uds, all_ifaces = parse_endpoint(args.hostport, DEFAULT_SERVE_PORT)
    else:
        host = port = uds = all_ifaces = None  # type: ignore

    # Collect origins and handle auth_host
    origins = getattr(args, "origins", None) or []
    if args.auth_host:
        # Normalize auth_host with scheme
        if "://" not in args.auth_host:
            args.auth_host = f"https://{args.auth_host}"

        validate_auth_host(args.auth_host, args.rp_id)
        from paskia.util import hostutil as _hostutil  # local import

        _hostutil.reload_config()

        # If origins are configured, ensure auth_host is included at top
        if origins:
            # Insert auth_host at the beginning (Passkey.__init__ will normalize/dedupe)
            origins.insert(0, args.auth_host)

    # Export configuration via single JSON env variable for worker processes
    # (PASKIA_DEVMODE is kept separate as it's externally defined)
    # All keys are always present; None is used where no value is configured
    import json

    config = {
        "rp_id": args.rp_id,
        "rp_name": args.rp_name or None,
        "origins": origins or None,
        "auth_host": args.auth_host or None,
    }
    os.environ["PASKIA_CONFIG"] = json.dumps(config)

    # One-time initialization + bootstrap before starting any server processes.
    # Lifespan in worker processes will call globals.init with bootstrap disabled.
    from paskia import globals as _globals  # local import

    asyncio.run(
        _globals.init(
            rp_id=config["rp_id"],
            rp_name=config["rp_name"],
            origins=config["origins"],
            bootstrap=True,
        )
    )

    # Print startup configuration
    from paskia.util import startupbox

    startupbox.print_startup_config(_globals.passkey.instance, args, host, port, uds)

    # Handle recover-admin command (no server start)
    if args.command == "reset":
        from paskia.fastapi import reset as reset_cmd  # local import

        exit_code = reset_cmd.run(getattr(args, "query", None))
        raise SystemExit(exit_code)

    if args.command == "serve":
        run_kwargs: dict = {
            "log_level": "info",
        }

        # Dev mode: enable reload when PASKIA_DEVMODE is set
        devmode = os.environ.get("PASKIA_DEVMODE") == "1"
        if devmode:
            # Security: dev mode must run on localhost:4402 to prevent
            # accidental public exposure of the Vite dev server
            if host != "localhost" or port != 4402:
                raise SystemExit(f"Dev mode requires localhost:4402, got {host}:{port}")
            run_kwargs["reload"] = True
            run_kwargs["reload_dirs"] = ["paskia"]

        if uds:
            run_kwargs["uds"] = uds
        else:
            if not all_ifaces:
                run_kwargs["host"] = host
                run_kwargs["port"] = port

        if all_ifaces and not uds:
            # Dev mode with all interfaces: use simple single-server approach
            if devmode:
                run_kwargs["host"] = "::"
                run_kwargs["port"] = port
                uvicorn.run("paskia.fastapi:app", **run_kwargs)
            else:
                # Production: run separate servers for IPv4 and IPv6
                from uvicorn import Config, Server  # noqa: E402 local import

                from paskia.fastapi import (
                    app as fastapi_app,  # noqa: E402 local import
                )

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
            uvicorn.run("paskia.fastapi:app", **run_kwargs)


if __name__ == "__main__":
    main()
