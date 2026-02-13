import argparse
import asyncio
import json
import logging
import os
from urllib.parse import urlparse

from fastapi_vue import server
from fastapi_vue.hostutil import parse_endpoint

from paskia import db
from paskia import globals as _globals
from paskia.bootstrap import bootstrap_if_needed
from paskia.config import PaskiaConfig
from paskia.db.background import flush
from paskia.db.structs import Config
from paskia.util import startupbox
from paskia.util.hostutil import normalize_origin

DEFAULT_PORT = 4401
DEVMODE = os.getenv("PASKIA_DEV") == "1"

EPILOG = """\
Example:
  paskia --rp-id example.com --rp-name "Example Corporation" --auth-host auth.example.com
"""


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

    # Handle clearing options
    if getattr(args, "auth_host", None) == "":
        args.auth_host = None
    if getattr(args, "rp_name", None) == "":
        args.rp_name = None
    if getattr(args, "listen", None) == "":
        args.listen = None

    # Init db and load stored config
    asyncio.run(db.init(rp_id=args.rp_id))
    stored_config = db.data().config

    # Apply defaults from stored config
    if args.rp_name is None and stored_config.rp_name is not None:
        args.rp_name = stored_config.rp_name
    if args.origins is None and stored_config.origins is not None:
        args.origins = stored_config.origins
    if args.auth_host is None and stored_config.auth_host is not None:
        args.auth_host = stored_config.auth_host
    if args.listen is None and stored_config.listen is not None:
        args.listen = stored_config.listen

    # Parse first endpoint for config display and site_url
    first_listen = args.listen[0] if isinstance(args.listen, list) else args.listen
    endpoints = parse_endpoint(first_listen, DEFAULT_PORT)

    # Extract host/port/uds from first endpoint for config display and site_url
    ep = endpoints[0] if endpoints else {}
    host = ep.get("host")
    port = ep.get("port")
    uds = ep.get("uds")

    # Collect and normalize origins, handle auth_host
    origins = [normalize_origin(o) for o in (getattr(args, "origins", None) or [])]
    if args.auth_host:
        # Normalize auth_host with scheme
        if "://" not in args.auth_host:
            args.auth_host = f"https://{args.auth_host}"

        validate_auth_host(args.auth_host, args.rp_id)

        # If origins are configured, ensure auth_host is included at top
        if origins:
            # Insert auth_host at the beginning
            origins.insert(0, args.auth_host)

    # Remove duplicates while preserving order
    seen = set()
    origins = [x for x in origins if not (x in seen or seen.add(x))]

    # Compute site_url and site_path for reset links
    # Priority: PASKIA_SITE_URL (explicit) > auth_host > first origin with localhost > http://localhost:port
    explicit_site_url = os.environ.get("PASKIA_SITE_URL")
    if explicit_site_url:
        # Explicit site URL from devserver or deployment config
        site_url = explicit_site_url.rstrip("/")
        site_path = "/" if args.auth_host else "/auth/"
    elif args.auth_host:
        site_url = args.auth_host.rstrip("/")
        site_path = "/"
    elif origins:
        # Find localhost origin if rp_id is localhost, else use first origin
        localhost_origin = (
            next((o for o in origins if "://localhost" in o), None)
            if args.rp_id == "localhost"
            else None
        )
        site_url = (localhost_origin or origins[0]).rstrip("/")
        site_path = "/auth/"
    elif args.rp_id == "localhost" and port:
        # Dev mode: use http with port
        site_url = f"http://localhost:{port}"
        site_path = "/auth/"
    else:
        site_url = f"https://{args.rp_id}"
        site_path = "/auth/"

    # Build runtime configuration
    config = PaskiaConfig(
        rp_id=args.rp_id,
        rp_name=args.rp_name or None,
        origins=origins or None,
        auth_host=args.auth_host or None,
        site_url=site_url,
        site_path=site_path,
        host=host,
        port=port,
        uds=uds,
    )

    # Export configuration via single JSON env variable for worker processes
    config_json = {
        "rp_id": config.rp_id,
        "rp_name": config.rp_name,
        "origins": config.origins,
        "auth_host": config.auth_host,
        "site_url": config.site_url,
        "site_path": config.site_path,
    }
    os.environ["PASKIA_CONFIG"] = json.dumps(config_json)

    startupbox.print_startup_config(config)

    # Build config to save (for bootstrap or explicit --save)
    cli_config = Config(
        rp_id=args.rp_id,
        rp_name=args.rp_name,
        origins=args.origins,
        auth_host=args.auth_host,
        listen=args.listen,
    )

    async def startup():
        await _globals.init(
            rp_id=config.rp_id,
            rp_name=config.rp_name,
            origins=config.origins,
            bootstrap=False,
        )
        # Pass config to bootstrap - it will be saved within the bootstrap transaction
        await bootstrap_if_needed(config=cli_config)
        # Also save config if --save was explicitly used (even without bootstrap)
        if args.save:
            await db.update_config(cli_config)
        await flush()

    asyncio.run(startup())

    dev = {"reload": True, "reload_dirs": ["paskia"]} if DEVMODE else {}
    server.run(
        "paskia.fastapi.mainapp:app",
        listen=args.listen,
        default_port=DEFAULT_PORT,
        log_level="warning",
        access_log=False,
        **dev,
    )


if __name__ == "__main__":
    main()