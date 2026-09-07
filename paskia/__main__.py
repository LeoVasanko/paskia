import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

import msgspec
from fastapi_vue import server
from kanta import Kanta

from paskia.db import legacy
from paskia.db.bootstrap import bootstrap, log_reset_link
from paskia.db.paths import db_file_path
from paskia.db.structs import DB, Config, DomainConfig
from paskia.domains import build as build_registry
from paskia.domains import configure as configure_domains
from paskia.domains import validate_config
from paskia.util import hostutil, startupbox
from paskia.util.constants import DEFAULT_PORT, DEVMODE
from paskia.util.runtime import ServeConfig

EPILOG = """\
Examples:
  paskia init example.com "Example Corporation"
  paskia migrate example.com
  paskia
"""


def _split_multi(values: list[str] | None) -> list[str]:
    """Split repeatable/comma-separated CLI values into a flat list."""
    result = []
    for value in values or []:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def _add_listen_option(p: argparse.ArgumentParser, help_extra: str = "") -> None:
    p.add_argument(
        "-l",
        "--listen",
        action="append",
        metavar="LISTEN",
        help=(
            "Endpoint to listen on (default: localhost:4401). "
            "Forms: host:port  port  :port  [ipv6]:port  unix:path  /path.sock"
        )
        + help_extra,
    )


def _load_stored_config(db_path: Path) -> Config:
    """Load the stored Config from disk using Kanta in read-only mode.

    This must not depend on PASKIA_CONFIG or the global lifecycle Kanta.
    Read-only opens never write or migrate the file.
    """
    kanta = Kanta(str(db_path), DB())

    async def _read() -> Config:
        await kanta.open(readonly=True)
        try:
            return kanta.data.config
        finally:
            await kanta.close()

    try:
        return asyncio.run(_read())
    except Exception as e:
        logging.exception("Failed to load database")
        raise SystemExit(f"{e}") from e


def _init_add_domain(db_path: Path, rp_id: str, rp_name: str | None, listen) -> None:
    """Add a domain to an existing database, or update an existing one's
    rp-name."""
    new_db = DB()
    kanta = Kanta(str(db_path), new_db)

    async def _update() -> str:
        await kanta.open()
        try:
            data = kanta.data
            if rp_id in data.config.domains:
                if rp_name is None and listen is None:
                    raise SystemExit(f"Domain {rp_id} is already configured.")
                with kanta.transaction("init:update_domain"):
                    if rp_name is not None:
                        data.config.domains[rp_id].rp_name = rp_name
                    if listen is not None:
                        data.config.listen = listen
                return f"Updated domain {rp_id}"
            new = DomainConfig(rp_name=rp_name, origins={f"**.{rp_id}": True})
            try:
                validate_config(
                    Config(
                        domains={**data.config.domains, rp_id: new},
                        listen=data.config.listen,
                    )
                )
            except ValueError as e:
                raise SystemExit(str(e)) from e
            with kanta.transaction("init:add_domain"):
                data.config.domains[rp_id] = new
                if listen is not None:
                    data.config.listen = listen
            return f"Added domain {rp_id}"
        finally:
            await kanta.close()

    print(f"✅ {asyncio.run(_update())}")


def cmd_init(args: argparse.Namespace) -> None:
    """Bootstrap a new paskia.kantadb, or add a domain to an existing one."""
    rp_id = (args.rp_id or "localhost").strip().lower()
    rp_name = args.rp_name or None
    listen = _split_multi(args.listen) or None
    try:
        hostutil.validate_rp_id(rp_id)
    except ValueError as e:
        raise SystemExit(str(e)) from e

    db_path = db_file_path()
    if db_path.exists():
        _init_add_domain(db_path, rp_id, rp_name, listen)
        return
    if found := legacy.find_legacy_databases():
        names = ", ".join(str(p) for p in found)
        raise SystemExit(
            f"Legacy database(s) found ({names}) — run 'paskia migrate' to "
            "convert, not 'paskia init'."
        )

    # Only rp-id and rp-name are bootstrap-time configuration; the new
    # domain starts with its whole subtree allowed ('**.{rp-id}') and
    # everything else (origin allow-list, auth host, related domains) is
    # set up afterwards via the admin interface. The bootstrap rp-name
    # exists so the very first admin registration ceremony already shows
    # the correct name.
    config = Config(
        domains={rp_id: DomainConfig(rp_name=rp_name, origins={f"**.{rp_id}": True})},
        listen=listen,
    )
    try:
        validate_config(config)
    except ValueError as e:
        raise SystemExit(str(e)) from e

    # Create the database; the kanta bootstrap callback seeds it (admin
    # user, org, permissions, reset token, the OIDC signing key).
    new_db = DB()
    kanta = Kanta(str(db_path), new_db)
    result = {}

    @kanta.bootstrap
    def _bootstrap(data: DB) -> None:
        result["passphrase"] = bootstrap(data, config=config)

    async def _create() -> None:
        async with kanta:
            pass

    try:
        asyncio.run(_create())
    except Exception as e:
        logging.exception("Failed to create database")
        db_path.unlink(missing_ok=True)
        raise SystemExit(f"{e}") from e

    configure_domains(listen=config.listen)
    registry = build_registry(config)
    startupbox.print_startup_config(registry, listen=config.listen)
    log_reset_link(
        registry.get(rp_id).reset_link_url(result["passphrase"]),
        "✅ Bootstrap completed!",
    )


def cmd_migrate(args: argparse.Namespace) -> None:
    """Convert a legacy <rp-id>.paskiadb database to paskia.kantadb."""
    rp_id = legacy.migrate_legacy_database(args.rp_id)
    print(f"✅ Converted legacy database to {db_file_path()} (domain: {rp_id})")


def cmd_serve(args: argparse.Namespace) -> None:
    """Open the combined database and serve all configured domains."""
    db_path = db_file_path()
    if not db_path.exists():
        if found := legacy.find_legacy_databases():
            names = ", ".join(str(p) for p in found)
            raise SystemExit(
                f"Database {db_path} not found, but legacy database(s) exist "
                f"({names}) — run 'paskia migrate' to convert."
            )
        raise SystemExit(f"Database {db_path} not found — run 'paskia init' first.")

    config = _load_stored_config(db_path)

    listen = _split_multi(args.listen) or config.listen
    configure_domains(listen=listen)
    try:
        registry = build_registry(config)
    except ValueError as e:
        raise SystemExit(f"Invalid stored configuration: {e}") from e
    # Sanitization warnings (serving is best-effort; fixing the stored config
    # is the admin's job via the admin interface) are logged by build().

    # Pass process-global serve parameters to the server process(es)
    os.environ["PASKIA_CONFIG"] = msgspec.json.encode(
        ServeConfig(listen=listen)
    ).decode()

    startupbox.print_startup_config(registry, listen=listen)

    # Run the server (spawns processes in dev mode)
    # tracerite, access logging and log config are handled by fastapi_vue.server;
    # we print our own startup config box, so disable the built-in one.
    server.run(
        "paskia.fastapi.mainapp:app",
        listen=listen,
        default_port=DEFAULT_PORT,
        server_header=False,
        startup_box=None,
        reload=Path(__file__).parent if DEVMODE else False,
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
    _add_listen_option(parser)

    init_parser = argparse.ArgumentParser(
        prog="paskia init",
        description="Bootstrap a new paskia.kantadb database in the current "
        "directory. With an existing database, adds the domain to it instead "
        "(or updates its rp-name).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    init_parser.add_argument(
        "rp_id",
        nargs="?",
        help="Relying Party ID of the initial domain (default: localhost). "
        "Further domains, origins and auth hosts are added via the admin "
        "interface — or with another 'paskia init <rp-id>'.",
    )
    init_parser.add_argument(
        "rp_name",
        nargs="?",
        help="Relying Party name of the domain (default: same as rp-id). "
        "Used by the initial admin registration; editable later via admin UI.",
    )
    _add_listen_option(init_parser, help_extra=" (stored in the database)")

    migrate_parser = argparse.ArgumentParser(
        prog="paskia migrate",
        description="Convert a legacy <rp-id>.paskiadb database to paskia.kantadb",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    migrate_parser.add_argument(
        "rp_id",
        nargs="?",
        help="rp-id of the legacy database to convert, selecting "
        "<rp-id>.paskiadb when several legacy candidates exist.",
    )

    argv = sys.argv[1:]
    if argv and argv[0] == "init":
        cmd_init(init_parser.parse_args(argv[1:]))
    elif argv and argv[0] == "migrate":
        cmd_migrate(migrate_parser.parse_args(argv[1:]))
    else:
        cmd_serve(parser.parse_args(argv))


if __name__ == "__main__":
    main()
