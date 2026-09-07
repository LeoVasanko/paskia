"""Legacy database format reader and converter.

Retains the msgspec structs used by the old ``<rp-id>.paskiadb/main.db``
format so existing databases can be opened and converted to the combined
``paskia.kantadb`` format. Only the structs whose shape differs from the
current schema are redefined here; unchanged structs are imported from
``paskia.db.structs``.

Assumes the on-disk records are in the latest legacy format (schema
migrations were discarded together with the old format). This module will
be deleted once legacy conversion is no longer supported.
"""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime
from pathlib import Path
from uuid import UUID

import msgspec
from kanta import Kanta

from paskia.db.paths import db_file_path, users_root_path
from paskia.db.structs import (
    DB,
    OIDC,
    Config,
    Credential,
    DomainConfig,
    Org,
    OriginEntry,
    Permission,
    ResetToken,
    Role,
    Session,
    User,
)


class LegacyConfig(msgspec.Struct, omit_defaults=True):
    """Pre-domains stored configuration (single rp-id per database)."""

    rp_id: str
    rp_name: str | None = None
    auth_host: str | None = None
    origins: list[str] | None = None
    listen: list[str] | None = None


class LegacyCredential(msgspec.Struct, dict=True):
    """Credential without the rp_id stamp."""

    credential_id: bytes
    user_uuid: UUID = msgspec.field(name="user")
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None
    last_verified: datetime | None = None


class LegacySession(msgspec.Struct, dict=True, omit_defaults=True):
    """Session without the rp_id/issuer stamps."""

    user_uuid: UUID = msgspec.field(name="user")
    credential_uuid: UUID = msgspec.field(name="credential")
    host: str
    ip: str
    user_agent: str
    validated: datetime
    client_uuid: UUID | None = msgspec.field(name="client", default=None)


class LegacyDB(msgspec.Struct, dict=True, omit_defaults=False):
    """Root structure of a legacy single-rp-id database."""

    config: LegacyConfig = msgspec.field(
        default_factory=lambda: LegacyConfig(rp_id="localhost")
    )
    permissions: dict[UUID, Permission] = {}
    orgs: dict[UUID, Org] = {}
    roles: dict[UUID, Role] = {}
    users: dict[UUID, User] = {}
    credentials: dict[UUID, LegacyCredential] = {}
    sessions: dict[str, LegacySession] = {}
    reset_tokens: dict[str, ResetToken] = {}
    oidc: OIDC = msgspec.field(default_factory=OIDC)


def _read_legacy(path: Path) -> LegacyDB:
    """Open a legacy database read-only and return its contents."""
    kanta = Kanta(str(path), LegacyDB())

    async def _read() -> LegacyDB:
        await kanta.open(readonly=True)
        return kanta.data

    return asyncio.run(_read())


def convert_legacy_database(src: Path, dst: Path) -> Config:
    """Convert a legacy main.db file into the combined kantadb format.

    Reads the legacy database at ``src`` and writes a fresh database at
    ``dst``. All credentials and sessions are stamped with the legacy
    database's rp-id; the OIDC provider carries over as-is (it is
    instance-global).
    Returns the converted (new-format) configuration.
    """
    old = _read_legacy(src)
    rp_id = old.config.rp_id

    from paskia.domains import origin_key  # noqa: PLC0415  (import cycle)

    origins: dict[str, bool | OriginEntry] = {}
    for origin in old.config.origins or []:
        origins[origin_key(origin)] = True
    if old.config.auth_host:
        origins[origin_key(old.config.auth_host)] = OriginEntry(auth_host=True)
    if not origins:
        # Legacy semantics: no origins configured = the whole rp-id domain
        # allowed. The new format requires explicit entries.
        origins[f"**.{rp_id}"] = True

    new_config = Config(
        domains={rp_id: DomainConfig(rp_name=old.config.rp_name, origins=origins)},
        listen=old.config.listen,
    )

    credentials = {
        uuid: Credential(
            credential_id=c.credential_id,
            user_uuid=c.user_uuid,
            aaguid=c.aaguid,
            public_key=c.public_key,
            sign_count=c.sign_count,
            created_at=c.created_at,
            rp_id=rp_id,
            last_used=c.last_used,
            last_verified=c.last_verified,
        )
        for uuid, c in old.credentials.items()
    }
    sessions = {
        key: Session(
            user_uuid=s.user_uuid,
            credential_uuid=s.credential_uuid,
            host=s.host,
            ip=s.ip,
            user_agent=s.user_agent,
            validated=s.validated,
            client_uuid=s.client_uuid,
            rp_id=rp_id,
        )
        for key, s in old.sessions.items()
    }

    converted = DB(
        config=new_config,
        permissions=old.permissions,
        orgs=old.orgs,
        roles=old.roles,
        users=old.users,
        credentials=credentials,
        sessions=sessions,
        reset_tokens=old.reset_tokens,
        oidc=old.oidc,
    )

    new_db = DB()
    kanta = Kanta(str(dst), new_db)

    @kanta.bootstrap
    def _seed(data: DB) -> None:
        data.config = converted.config
        data.permissions = converted.permissions
        data.orgs = converted.orgs
        data.roles = converted.roles
        data.users = converted.users
        data.credentials = converted.credentials
        data.sessions = converted.sessions
        data.reset_tokens = converted.reset_tokens
        data.oidc = converted.oidc

    async def _write() -> None:
        async with kanta:
            pass

    asyncio.run(_write())
    return new_config


def find_legacy_databases(cwd: Path | None = None) -> list[Path]:
    """Find legacy ``*.paskiadb`` databases in a directory.

    A candidate is either a directory containing ``main.db`` or a legacy
    single-file database. Empty directories and non-matching files are
    ignored.
    """
    cwd = cwd or Path.cwd()
    candidates = []
    for entry in sorted(cwd.glob("*.paskiadb")):
        if entry.is_dir():
            if (entry / "main.db").is_file():
                candidates.append(entry)
        elif entry.is_file():
            candidates.append(entry)
    return candidates


def migrate_legacy_database(rp_id: str | None = None) -> str:
    """Convert a legacy database to ``paskia.kantadb``.

    With ``rp_id``, selects the ``<rp-id>.paskiadb`` candidate by name;
    without it, exactly one candidate must exist. Returns the migrated
    domain's rp-id. The converted legacy directory/file is renamed aside
    to ``<name>.converted-bak`` rather than deleted.

    Raises SystemExit when ``paskia.kantadb`` already exists, when no
    candidate matches, or when several candidates exist and no ``rp_id``
    was given to select one.
    """
    target = db_file_path()
    if target.exists():
        raise SystemExit(f"Database {target} already exists — nothing to migrate.")
    candidates = find_legacy_databases()
    if rp_id is not None:
        name = f"{rp_id}.paskiadb"
        matches = [c for c in candidates if c.name == name]
        if not matches:
            found = ", ".join(str(c) for c in candidates) or "none"
            raise SystemExit(
                f"No legacy database {name} in this directory (candidates: {found})."
            )
        src = matches[0]
    elif not candidates:
        raise SystemExit("No legacy *.paskiadb database found — nothing to migrate.")
    elif len(candidates) > 1:
        names = ", ".join(str(c) for c in candidates)
        raise SystemExit(
            f"Multiple legacy databases found ({names}) — select one with "
            "'paskia migrate <rp-id>'."
        )
    else:
        src = candidates[0]
    legacy_file = src / "main.db" if src.is_dir() else src
    config = convert_legacy_database(legacy_file, target)

    # Move persisted user files (avatars) to the new data root
    legacy_users = src / "users" if src.is_dir() else None
    if legacy_users is not None and legacy_users.is_dir():
        target_users = users_root_path(create_root=True)
        for child in legacy_users.iterdir():
            shutil.move(str(child), str(target_users / child.name))

    shutil.move(str(src), str(src.with_name(src.name + ".converted-bak")))
    return next(iter(config.domains))
