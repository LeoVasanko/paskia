import argparse
import logging
import os

import msgspec
from fastapi_vue import server
from fastapi_vue.hostutil import parse_endpoints

from paskia.db.jsonl import load_readonly
from paskia.util import startupbox
from paskia.util.hostutil import (
    normalize_auth_host_and_origins,
    normalize_origin,
    validate_auth_host,
)
from paskia.util.runtime import RuntimeConfig

DEFAULT_PORT = 4401
DEVMODE = os.getenv("PASKIA_DEV") == "1"

EPILOG = """\
Example:
  paskia --rp-id example.com --rp-name "Example Corporation" --auth-host auth.example.com
"""


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
        help=("Dedicated authentication site (optionally with scheme/port)"),
    )
    p.add_argument(
        "--save",
        action="store_true",
        help="Save the CLI options to database for future runs.",
    )


def main():
    # Configure logging to remove the "ERROR:root:" prefix
    logging.basicConfig(level=logging.INFO, format="%(message)s", force=True)

    parser = argparse.ArgumentParser(
        prog="paskia",
        description="Paskia authentication server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )

    parser.add_argument(
        "-l",
        "--listen",
        action="append",
        metavar="LISTEN",
        help=(
            "Endpoint to listen on (default: localhost:4401). "
            "Forms: host:port  port  :port  [ipv6]:port  unix:path  /path.sock"
        ),
    )
    add_common_options(parser)

    args = parser.parse_args()

    # Load stored config (read-only, no writes, no global state)
    db_path = os.environ.get("PASKIA_DB", f"{args.rp_id}.paskiadb")
    config = load_readonly(db_path, rp_id=args.rp_id).config

    # Override stored config with CLI args, or clear with empty string
    if args.rp_name is not None:
        config.rp_name = args.rp_name or None
    if args.auth_host is not None:
        config.auth_host = args.auth_host or None
    if args.origins is not None:
        config.origins = None if args.origins == [""] else args.origins
    if args.listen is not None:
        config.listen = None if args.listen == [""] else args.listen

    # Process and normalize auth_host and origins
    try:
        validate_auth_host(config.auth_host, config.rp_id) if config.auth_host else None
    except ValueError as e:
        raise SystemExit(str(e))
    if config.origins:
        config.origins = [normalize_origin(o) for o in config.origins]
    config.auth_host, config.origins = normalize_auth_host_and_origins(
        config.auth_host, config.origins
    )

    # Parse first endpoint for site_url fallback
    ep = next(iter(parse_endpoints(config.listen, DEFAULT_PORT)), {})
    port = ep.get("port")

    # Compute site_url and site_path
    # Priority: auth_host > origins[0] > PASKIA_VITE_URL > http://localhost:port > https://rp_id
    site_path = "/auth/"
    if config.auth_host:
        site_url, site_path = config.auth_host, "/"
    elif config.origins:
        site_url = config.origins[0]
    elif vite_url := os.environ.get("PASKIA_VITE_URL"):
        site_url = vite_url.rstrip("/")  # Devserver
    elif config.rp_id == "localhost" and port:
        site_url = f"http://localhost:{port}"  # Backend directly if we can
    else:
        site_url = f"https://{config.rp_id}"  # Assume external reverse proxy

    # Build runtime configuration for the server
    runtime = RuntimeConfig(
        config=config,
        site_url=site_url,
        site_path=site_path,
        save=args.save,
    )
    startupbox.print_startup_config(runtime)
    os.environ["PASKIA_CONFIG"] = msgspec.json.encode(runtime).decode()

    # Run the server (spawns processes in dev mode)
    dev = {"reload": True, "reload_dirs": ["paskia"]} if DEVMODE else {}
    server.run(
        "paskia.fastapi.mainapp:app",
        listen=config.listen,
        default_port=DEFAULT_PORT,
        log_level="warning",
        access_log=False,
        **dev,
    )


if __name__ == "__main__":
    main()
