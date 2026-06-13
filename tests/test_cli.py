"""Tests for the CLI entry point in paskia/__main__.py."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from kanta import Kanta

from paskia.__main__ import main
from paskia.db.structs import DB, Config
from paskia.util.runtime import clear_config_cache
from paskia.util.runtime import config as runtime_config


@pytest.fixture
def cli_run(monkeypatch):
    """Run the CLI main() with the given args and return the RuntimeConfig."""

    def _run(*args: str, db_root: str | None = None) -> Any:
        env = os.environ.copy()
        if db_root is not None:
            env["PASKIA_DB"] = db_root
        monkeypatch.setattr(os, "environ", env)

        monkeypatch.setattr(sys, "argv", ["paskia", *args])
        monkeypatch.setattr("fastapi_vue.server.run", lambda *_args, **_kw: None)
        monkeypatch.setattr(
            "paskia.util.startupbox.print_startup_config", lambda _rt: None
        )
        monkeypatch.setattr("logging.basicConfig", lambda **_kw: None)

        clear_config_cache()
        main()
        runtime = runtime_config()
        clear_config_cache()
        return runtime

    return _run


async def _write_config(db_path: Path, config: Config) -> None:
    """Write a Config into a JSONL database file using Kanta.

    The initial root uses a different rp_id so the stored diff includes the
    target rp_id (required because Config omits defaults when diffing).
    """
    kanta = Kanta(
        str(db_path),
        DB(config=Config(rp_id="uninitialized.invalid")),
        migrations="paskia.db.migrations",
    )
    kanta.ctx.rp_id = config.rp_id
    await kanta.open()
    with kanta.transaction("test:write_config"):
        kanta.data.config = config
    await kanta.close()


def write_config(db_path: Path, config: Config) -> None:
    """Synchronous wrapper for _write_config."""
    asyncio.run(_write_config(db_path, config))


def test_cli_defaults(cli_run):
    with tempfile.TemporaryDirectory() as tmp:
        runtime = cli_run("--rp-id", "localhost", db_root=tmp)

    assert runtime.config.rp_id == "localhost"
    assert runtime.config.rp_name is None
    assert runtime.config.auth_host is None
    assert runtime.config.origins is None
    assert runtime.site_url == "http://localhost:4401"
    assert runtime.site_path == "/auth/"
    assert runtime.save is False


def test_cli_explicit_options(cli_run):
    runtime = cli_run(
        "--rp-id",
        "example.com",
        "--rp-name",
        "Example Corp",
        "--auth-host",
        "auth.example.com",
        "--origin",
        "https://app.example.com",
    )

    assert runtime.config.rp_id == "example.com"
    assert runtime.config.rp_name == "Example Corp"
    assert runtime.config.auth_host == "https://auth.example.com"
    assert runtime.config.origins == [
        "https://auth.example.com",
        "https://app.example.com",
    ]
    assert runtime.site_url == "https://auth.example.com"
    assert runtime.site_path == "/"


def test_cli_loads_stored_config(cli_run):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "main.db"
        write_config(
            db_path,
            Config(
                rp_id="example.com",
                rp_name="Stored Name",
                origins=["https://stored.example.com"],
            ),
        )
        runtime = cli_run("--rp-id", "example.com", db_root=tmp)

    assert runtime.config.rp_name == "Stored Name"
    assert runtime.config.origins == ["https://stored.example.com"]
    assert runtime.site_url == "https://stored.example.com"


def test_cli_overrides_stored_config(cli_run):
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "main.db"
        write_config(db_path, Config(rp_id="example.com", rp_name="Stored Name"))
        runtime = cli_run(
            "--rp-id", "example.com", "--rp-name", "Overridden", db_root=tmp
        )

    assert runtime.config.rp_name == "Overridden"


def test_cli_save_flag(cli_run):
    runtime = cli_run("--save")
    assert runtime.save is True


def test_cli_invalid_auth_host(cli_run):
    with pytest.raises(SystemExit):
        cli_run("--rp-id", "example.com", "--auth-host", "notsub.example.org")


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "paskia", "--help"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Paskia authentication server" in result.stdout
