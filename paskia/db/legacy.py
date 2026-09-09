"""Legacy database format reader, converter and database merging.

Retains the msgspec structs used by the old ``<rp-id>.paskiadb/main.db``
format so existing databases can be opened and converted to the combined
``paskia.kantadb`` format, and implements the merge of incoming data
(legacy or current format) into an existing ``paskia.kantadb``. Only the
structs whose shape differs from the current schema are redefined here;
unchanged structs are imported from ``paskia.db.structs``.

Assumes the on-disk records are in the latest legacy format (schema
migrations were discarded together with the old format). The legacy
structs will be deleted once legacy conversion is no longer supported.
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


def _read_kantadb(path: Path) -> DB:
    """Open a current-format database read-only and return its contents."""
    kanta = Kanta(str(path), DB())

    async def _read() -> DB:
        await kanta.open(readonly=True)
        return kanta.data

    return asyncio.run(_read())


def _legacy_to_db(old: LegacyDB) -> DB:
    """Convert legacy database contents to the combined kantadb format.

    All credentials and sessions are stamped with the legacy database's
    rp-id; the OIDC provider carries over as-is (it is instance-global).
    """
    rp_id = old.config.rp_id

    from paskia.domains import origin_key  # noqa: PLC0415  (import cycle)

    origins: dict[str, bool | OriginEntry] = {}
    for origin in old.config.origins or []:
        origins[origin_key(origin)] = True
    if old.config.auth_host:
        origins[origin_key(old.config.auth_host)] = OriginEntry(auth_host=True)
    if not old.config.origins:
        # Legacy semantics: no origins configured = the whole rp-id domain
        # allowed, regardless of a dedicated auth host. The new format
        # requires explicit entries.
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
    return converted


def _migration_label(incoming: DB) -> str:
    """Transaction label for a migration; multiple rp-ids join with slashes."""
    return f"migrate:cli:{'/'.join(incoming.config.domains)}"


def _write_fresh(data: DB, dst: Path, label: str) -> None:
    """Write a fresh database at ``dst`` with the given contents."""
    new_db = DB()
    kanta = Kanta(str(dst), new_db)

    @kanta.bootstrap(action=label)
    def _seed(target: DB) -> None:
        target.config = data.config
        target.permissions = data.permissions
        target.orgs = data.orgs
        target.roles = data.roles
        target.users = data.users
        target.credentials = data.credentials
        target.sessions = data.sessions
        target.reset_tokens = data.reset_tokens
        target.oidc = data.oidc

    async def _write() -> None:
        async with kanta:
            pass

    asyncio.run(_write())


def convert_legacy_database(src: Path, dst: Path) -> Config:
    """Convert a legacy main.db file into the combined kantadb format.

    Reads the legacy database at ``src`` and writes a fresh database at
    ``dst``. Returns the converted (new-format) configuration.
    """
    converted = _legacy_to_db(_read_legacy(src))
    _write_fresh(converted, dst, _migration_label(converted))
    return converted.config


def _merge_data(data: DB, incoming: DB) -> None:
    """Merge ``incoming`` contents into the live ``data`` object.

    Records are uuid-keyed (or hash-keyed for sessions/reset tokens), so
    identical keys denote the same item: existing entries win, new entries
    are added. Domains merge per rp-id with a union of allowed origins;
    the existing instance's listen endpoints and OIDC signing key win.
    """
    for rp_id, domain in incoming.config.domains.items():
        existing = data.config.domains.get(rp_id)
        if existing is None:
            data.config.domains[rp_id] = domain
            continue
        for origin, entry in domain.origins.items():
            existing.origins.setdefault(origin, entry)
        if existing.rp_name is None:
            existing.rp_name = domain.rp_name
    for bucket in (
        "permissions",
        "orgs",
        "roles",
        "users",
        "credentials",
        "sessions",
        "reset_tokens",
    ):
        target_map = getattr(data, bucket)
        for key, value in getattr(incoming, bucket).items():
            target_map.setdefault(key, value)
    for uuid, client in incoming.oidc.clients.items():
        data.oidc.clients.setdefault(uuid, client)
    if data.oidc.key is None:
        data.oidc.key = incoming.oidc.key


def merge_database(dst: Path, incoming: DB) -> None:
    """Merge ``incoming`` contents into the existing database at ``dst``."""
    kanta = Kanta(str(dst), DB())

    async def _merge() -> None:
        async with kanta:
            with kanta.transaction(_migration_label(incoming)):
                _merge_data(kanta.data, incoming)

    asyncio.run(_merge())


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


def _resolve_source(source: str | None) -> tuple[Path, bool, Path, Path | None]:
    """Resolve the migrate source.

    ``source`` may be an rp-id (selecting ``<rp-id>.paskiadb`` in the
    current directory), a path to a legacy ``*.paskiadb`` directory or
    file, or a path to a current-format ``*.kantadb`` file. Without
    ``source``, exactly one legacy candidate must exist in the current
    directory.

    Returns ``(db_file, is_legacy, users_dir, rename_target)`` where
    ``users_dir`` holds auxiliary user files (avatars) and
    ``rename_target`` is the legacy directory/file to rename aside after
    a successful migration (None for current-format sources).
    """

    def legacy(src: Path) -> tuple[Path, bool, Path, Path]:
        return (
            src / "main.db" if src.is_dir() else src,
            True,
            src / "users" if src.is_dir() else src.parent / "users",
            src,
        )

    if source is not None:
        path = Path(source)
        if path.is_dir():
            if (path / "main.db").is_file():
                return legacy(path)
            raise SystemExit(f"No legacy main.db found in directory {path}.")
        if path.is_file():
            if path.suffix == ".paskiadb":
                return legacy(path)
            return path, False, path.parent / "paskia.data" / "users", None
        # Not a path: treat as rp-id selecting a legacy candidate by name
        name = f"{source}.paskiadb"
        matches = [c for c in find_legacy_databases() if c.name == name]
        if not matches:
            found = ", ".join(str(c) for c in find_legacy_databases()) or "none"
            raise SystemExit(
                f"No legacy database {name} in this directory (candidates: {found})."
            )
        return legacy(matches[0])
    candidates = find_legacy_databases()
    if not candidates:
        raise SystemExit("No legacy *.paskiadb database found — nothing to migrate.")
    if len(candidates) > 1:
        names = ", ".join(str(c) for c in candidates)
        raise SystemExit(
            f"Multiple legacy databases found ({names}) — select one with "
            "'paskia migrate <rp-id>'."
        )
    return legacy(candidates[0])


def _move_user_files(src_users: Path) -> None:
    """Move persisted user files (avatars) to the new data root."""
    if not src_users.is_dir():
        return
    target_users = users_root_path(create_root=True)
    for child in src_users.iterdir():
        if (target_users / child.name).exists():
            continue
        shutil.move(str(child), str(target_users / child.name))


def migrate_database(source: str | None = None) -> list[str]:
    """Convert or merge a database into ``paskia.kantadb``.

    The source may be a legacy ``<rp-id>.paskiadb`` database (selected by
    rp-id or path) or a current-format ``*.kantadb`` file given by path.
    When ``paskia.kantadb`` already exists, the incoming data is merged
    into it (uuid-keyed records make conflicts a non-issue); otherwise a
    fresh database is written. Returns the migrated domains' rp-ids. A
    migrated legacy source is renamed aside to ``<name>.converted-bak``
    rather than deleted; a merged kantadb source is left in place.
    """
    target = db_file_path()
    db_file, is_legacy, users_dir, rename_target = _resolve_source(source)
    if db_file.resolve() == target.resolve():
        raise SystemExit(f"{db_file} is the active database — nothing to migrate.")

    incoming = (
        _legacy_to_db(_read_legacy(db_file)) if is_legacy else _read_kantadb(db_file)
    )
    rp_ids = list(incoming.config.domains)

    if target.exists():
        merge_database(target, incoming)
    else:
        _write_fresh(incoming, target, _migration_label(incoming))

    _move_user_files(users_dir)
    if rename_target is not None and rename_target.exists():
        shutil.move(
            str(rename_target),
            str(rename_target.with_name(rename_target.name + ".converted-bak")),
        )
    return rp_ids
