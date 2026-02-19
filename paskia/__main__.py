import argparse
import json
import logging
import os
from urllib.parse import urlparse

from fastapi_vue import server
from fastapi_vue.hostutil import parse_endpoints

from paskia.config import PaskiaConfig
from paskia.db.jsonl import load_readonly
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
        default=[],
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

    # Read-only load to get stored config (no writes, no global state)
    db_path = os.environ.get("PASKIA_DB", f"{args.rp_id}.paskiadb")
    stored_db = load_readonly(db_path, rp_id=args.rp_id)
    stored_config = stored_db.config

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
    ep = next(iter(parse_endpoints(args.listen, DEFAULT_PORT)), {})
    host, port, uds = ep.get("host"), ep.get("port"), ep.get("uds")

    # Process and normalize auth_host
    if args.auth_host:
        if "://" not in args.auth_host:
            args.auth_host = f"https://{args.auth_host}"
        args.auth_host = args.auth_host.rstrip("/")
        validate_auth_host(args.auth_host, args.rp_id)
        args.origins.insert(0, args.auth_host)  # Ensure first in origins

    # Normalize, strip trailing slashes, and deduplicate while preserving order
    origins = list({normalize_origin(o).rstrip("/"): ... for o in (args.origins)})

    # Compute site_url and site_path for reset links
    # Priority: auth_host > first configured origin > PASKIA_VITE_URL (devserver) > http://localhost:port > https://rp_id
    site_path = "/auth/"
    if args.auth_host:
        site_url = args.auth_host
        site_path = "/"
    elif origins:
        # Find localhost origin if rp_id is localhost, else use first origin
        localhost_origin = (
            next((o for o in origins if "://localhost" in o), None)
            if args.rp_id == "localhost"
            else None
        )
        site_url = localhost_origin or origins[0]
    elif vite_url := os.environ.get("PASKIA_VITE_URL"):
        site_url = vite_url.rstrip("/")  # Devserver
    elif args.rp_id == "localhost" and port:
        site_url = f"http://localhost:{port}"  # Backend directly if we can
    else:
        site_url = f"https://{args.rp_id}"  # Assume external reverse proxy

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
    # Include cli_config and save flag so lifespan can handle bootstrap/persistence
    cli_config = {
        "rp_id": args.rp_id,
        "rp_name": args.rp_name,
        "origins": args.origins,
        "auth_host": args.auth_host,
        "listen": args.listen,
    }
    config_json = {
        "rp_id": config.rp_id,
        "rp_name": config.rp_name,
        "origins": config.origins,
        "auth_host": config.auth_host,
        "site_url": config.site_url,
        "site_path": config.site_path,
        "save": args.save,
        "cli_config": cli_config,
    }
    os.environ["PASKIA_CONFIG"] = json.dumps(config_json)

    startupbox.print_startup_config(config)

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
