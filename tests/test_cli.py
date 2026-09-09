"""Tests for the CLI entry point in paskia/__main__.py.

The CLI is split into ``paskia init`` (create the combined paskia.kantadb
with the initial domain(s)), ``paskia migrate`` (convert a legacy
``<rp-id>.paskiadb`` database, or merge a legacy/current database into an
existing paskia.kantadb), and bare ``paskia`` (serve the stored
domains; never migrates).
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import msgspec
import pytest
from kanta import Kanta

from paskia.__main__ import _load_stored_config, main
from paskia.db import legacy
from paskia.db.structs import DB, Config, DomainConfig
from paskia.util.runtime import ServeConfig, clear_cache


@pytest.fixture
def run_cli(monkeypatch, tmp_path):
    """Run the CLI main() in a temporary working directory.

    Returns a callable; server.run and the startup box are stubbed out.
    The returned dict records the server.run invocation (if any).
    """
    monkeypatch.chdir(tmp_path)
    calls: dict = {}
    monkeypatch.setattr(
        "fastapi_vue.server.run",
        lambda app, **kw: calls.update({"app": app, **kw}),
    )
    monkeypatch.setattr(
        "paskia.util.startupbox.print_startup_config", lambda *a, **kw: None
    )
    monkeypatch.setattr("logging.basicConfig", lambda **kw: None)
    # Isolate environment mutations (PASKIA_CONFIG) from other tests
    env = os.environ.copy()
    env.pop("PASKIA_CONFIG", None)
    env.pop("PASKIA_VITE_URL", None)
    monkeypatch.setattr(os, "environ", env)

    def _run(*args: str) -> dict:
        monkeypatch.setattr(sys, "argv", ["paskia", *args])
        clear_cache()
        try:
            main()
        finally:
            clear_cache()
        return calls

    return _run


def stored_config(tmp_path: Path) -> Config:
    """Read back the stored combined configuration."""
    return _load_stored_config(tmp_path / "paskia.kantadb")


def write_legacy_db(root: Path, config: legacy.LegacyConfig) -> Path:
    """Create a legacy-format database directory <rp-id>.paskiadb/main.db."""
    src_dir = root / f"{config.rp_id}.paskiadb"
    src_dir.mkdir()
    db_file = src_dir / "main.db"

    async def _write() -> None:
        kanta = Kanta(str(db_file), legacy.LegacyDB())
        await kanta.open()
        with kanta.transaction("test:seed"):
            kanta.data.config = config
        await kanta.close()

    asyncio.run(_write())
    return src_dir


def test_init_defaults(run_cli, tmp_path):
    run_cli("init")

    config = stored_config(tmp_path)
    assert list(config.domains) == ["localhost"]
    assert config.domains["localhost"].rp_name is None
    assert config.domains["localhost"].origins == {"**.localhost": True}
    assert config.listen is None


def test_init_full_options(run_cli, tmp_path):
    run_cli("init", "example.com", "Example Corp", "--listen", "4402")

    config = stored_config(tmp_path)
    domain = config.domains["example.com"]
    assert domain.rp_name == "Example Corp"
    assert domain.origins == {"**.example.com": True}
    assert config.listen == ["4402"]


def test_init_adds_domains_to_existing_database(run_cli, tmp_path):
    """Further rp-ids are added by repeating init; no comma separation."""
    run_cli("init", "company.com")
    run_cli("init", "app.com")
    run_cli("init", "pro.com", "Pro Corp")

    config = stored_config(tmp_path)
    assert list(config.domains) == ["company.com", "app.com", "pro.com"]
    assert config.domains["pro.com"].rp_name == "Pro Corp"


def test_init_seeds_one_global_oidc_key(run_cli, tmp_path):
    """OIDC is instance-global: init seeds a single signing key."""
    run_cli("init", "company.com")
    run_cli("init", "app.com")
    assert converted_oidc_key(tmp_path) is not None


def converted_oidc_key(tmp_path):
    async def _read():
        new_db = DB()
        kanta = Kanta(str(tmp_path / "paskia.kantadb"), new_db)
        await kanta.open(readonly=True)
        try:
            return kanta.data.oidc.key
        finally:
            await kanta.close()

    return asyncio.run(_read())


def test_init_updates_rp_name_of_existing_domain(run_cli, tmp_path):
    run_cli("init", "example.com", "Old Name")
    run_cli("init", "example.com", "New Name")
    assert stored_config(tmp_path).domains["example.com"].rp_name == "New Name"


def test_init_noop_on_existing_domain(run_cli):
    run_cli("init")
    with pytest.raises(SystemExit, match="already configured"):
        run_cli("init")


def test_init_refuses_legacy_database(run_cli, tmp_path):
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="example.com"))
    with pytest.raises(SystemExit):
        run_cli("init")


def test_init_rejects_removed_options(run_cli):
    """Origins and auth hosts are admin-interface configuration, not init's."""
    with pytest.raises(SystemExit):
        run_cli("init", "example.com", "--auth-host", "auth.example.com")
    with pytest.raises(SystemExit):
        run_cli("init", "--origin", "https://app.example.com")


def test_serve_requires_database(run_cli):
    with pytest.raises(SystemExit, match="paskia init"):
        run_cli()


def test_serve_uses_stored_config(run_cli, tmp_path):
    run_cli("init", "example.com", "Stored Name")
    calls = run_cli()

    assert calls["app"] == "paskia.fastapi.mainapp:app"
    assert calls["listen"] is None  # stored listen (None) used
    serve = msgspec.json.decode(os.environ["PASKIA_CONFIG"].encode(), type=ServeConfig)
    assert serve.listen is None


def test_serve_listen_override_not_persisted(run_cli, tmp_path):
    run_cli("init", "--listen", "4402")
    calls = run_cli("--listen", "4403")

    assert calls["listen"] == ["4403"]
    serve = msgspec.json.decode(os.environ["PASKIA_CONFIG"].encode(), type=ServeConfig)
    assert serve.listen == ["4403"]
    # Stored config keeps the original listen value
    assert stored_config(tmp_path).listen == ["4402"]


def test_serve_suggests_migrate_when_legacy_present(run_cli, tmp_path):
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="example.com"))
    with pytest.raises(SystemExit, match="paskia migrate"):
        run_cli()


def test_migrate_converts_legacy_database(run_cli, tmp_path):
    src_dir = write_legacy_db(
        tmp_path, legacy.LegacyConfig(rp_id="example.com", rp_name="Legacy Name")
    )
    # Persisted user files move to the new data root
    avatar = src_dir / "users" / "019c6831-84cf-7b88-b66c-c8165890b7c5"
    avatar.mkdir(parents=True)
    (avatar / "profile.webp").write_bytes(b"RIFF1234WEBP")

    run_cli("migrate")

    config = stored_config(tmp_path)
    assert list(config.domains) == ["example.com"]
    assert config.domains["example.com"].rp_name == "Legacy Name"
    # Migration transaction is labeled with the migrated rp-id
    assert b"migrate:cli:example.com" in (tmp_path / "paskia.kantadb").read_bytes()
    # Legacy directory renamed aside, user files moved over
    assert not src_dir.exists()
    assert (tmp_path / "example.com.paskiadb.converted-bak").is_dir()
    assert (
        tmp_path
        / "paskia.data"
        / "users"
        / "019c6831-84cf-7b88-b66c-c8165890b7c5"
        / "profile.webp"
    ).read_bytes() == b"RIFF1234WEBP"


def test_migrate_multiple_legacy_databases_require_rp_id(run_cli, tmp_path):
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="one.com"))
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="two.com"))
    with pytest.raises(SystemExit, match="paskia migrate"):
        run_cli("migrate")


def test_migrate_explicit_rp_id_selects_candidate(run_cli, tmp_path):
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="one.com"))
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="two.com"))

    run_cli("migrate", "two.com")

    config = stored_config(tmp_path)
    assert list(config.domains) == ["two.com"]
    # The other candidate is left in place
    assert (tmp_path / "one.com.paskiadb").is_dir()
    assert (tmp_path / "two.com.paskiadb.converted-bak").is_dir()


def test_migrate_unknown_rp_id(run_cli, tmp_path):
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="one.com"))
    with pytest.raises(SystemExit, match="nope.com.paskiadb"):
        run_cli("migrate", "nope.com")


def test_migrate_merges_legacy_into_existing_database(run_cli, tmp_path):
    """An existing paskia.kantadb is not refused — data is merged in."""
    run_cli("init", "company.com", "Company")
    write_legacy_db(tmp_path, legacy.LegacyConfig(rp_id="example.com", rp_name="Ex"))

    run_cli("migrate")

    config = stored_config(tmp_path)
    assert list(config.domains) == ["company.com", "example.com"]
    assert config.domains["example.com"].rp_name == "Ex"
    assert (tmp_path / "example.com.paskiadb.converted-bak").is_dir()


def write_kantadb(root: Path, domains: dict, name: str = "paskia.kantadb") -> Path:
    """Create a current-format database file with the given config domains."""
    db_file = root / name

    config = Config(
        domains={rp_id: DomainConfig(rp_name=name_) for rp_id, name_ in domains.items()}
    )

    async def _write() -> None:
        new_db = DB()
        kanta = Kanta(str(db_file), new_db)

        @kanta.bootstrap
        def _seed(data: DB) -> None:
            data.config = config

        async with kanta:
            pass

    asyncio.run(_write())
    return db_file


def test_migrate_merges_kantadb_into_existing_database(run_cli, tmp_path):
    run_cli("init", "company.com", "Company")
    src = write_kantadb(tmp_path, {"other.com": "Other"}, name="other.kantadb")

    run_cli("migrate", str(src))

    config = stored_config(tmp_path)
    assert list(config.domains) == ["company.com", "other.com"]
    assert config.domains["other.com"].rp_name == "Other"
    # Current-format sources are left in place
    assert src.is_file()
    assert b"migrate:cli:other.com" in (tmp_path / "paskia.kantadb").read_bytes()


def test_migrate_merge_label_combines_rp_ids(run_cli, tmp_path):
    """A multi-domain source merges in one transaction, rp-ids slash-joined."""
    run_cli("init", "company.com")
    src = write_kantadb(tmp_path, {"one.com": "One", "two.com": "Two"}, name="x.kantadb")

    run_cli("migrate", str(src))

    assert b"migrate:cli:one.com/two.com" in (tmp_path / "paskia.kantadb").read_bytes()


def test_migrate_merges_shared_domain_origins(run_cli, tmp_path):
    """Same rp-id in both databases: origins union, existing rp-name wins."""
    run_cli("init", "example.com", "Existing Name")
    src = write_kantadb(tmp_path, {"example.com": "Incoming Name"}, name="x.kantadb")

    run_cli("migrate", str(src))

    domain = stored_config(tmp_path).domains["example.com"]
    assert domain.rp_name == "Existing Name"
    assert set(domain.origins) == {"**.example.com"}


def test_migrate_refuses_active_database_as_source(run_cli):
    run_cli("init")
    with pytest.raises(SystemExit, match="active database"):
        run_cli("migrate", "paskia.kantadb")


def test_migrate_kantadb_to_fresh_target(run_cli, tmp_path):
    src_dir = tmp_path / "elsewhere"
    src_dir.mkdir()
    src = write_kantadb(src_dir, {"other.com": "Other"})

    run_cli("migrate", str(src))

    assert list(stored_config(tmp_path).domains) == ["other.com"]


def test_migrate_without_legacy_database(run_cli):
    with pytest.raises(SystemExit, match="No legacy"):
        run_cli("migrate")


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "paskia", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Paskia authentication server" in result.stdout


def test_cli_init_help():
    result = subprocess.run(
        [sys.executable, "-m", "paskia", "init", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Bootstrap" in result.stdout


def test_cli_migrate_help():
    result = subprocess.run(
        [sys.executable, "-m", "paskia", "migrate", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Convert" in result.stdout
