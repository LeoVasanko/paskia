from __future__ import annotations

import os
import shutil
from pathlib import Path


def db_root_path(*, rp_id: str = "localhost") -> Path:
    """Return the configured persistence root directory."""
    return Path(os.environ.get("PASKIA_DB", f"{rp_id}.paskiadb"))


def db_file_path(*, rp_id: str = "localhost", create_root: bool = False) -> Path:
    """Return the JSONL database file path under the persistence root."""
    root = db_root_path(rp_id=rp_id)

    if root.is_file():
        _migrate_legacy_db_file(root)

    if create_root:
        root.mkdir(parents=True, exist_ok=True)

    return root / "main.db"


def users_root_path(*, rp_id: str = "localhost", create_root: bool = False) -> Path:
    """Return the filesystem root for persisted user files."""
    root = db_root_path(rp_id=rp_id)

    if root.is_file():
        _migrate_legacy_db_file(root)

    if create_root:
        root.mkdir(parents=True, exist_ok=True)

    return root / "users"


def _migrate_legacy_db_file(legacy_path: Path) -> None:
    """Upgrade a legacy single-file database path into a directory root."""
    temp_root = legacy_path.parent / f".{legacy_path.name}.migrating"
    shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.unlink(missing_ok=True)

    temp_root.mkdir(parents=True)
    legacy_path.replace(temp_root / "main.db")
    temp_root.rename(legacy_path)
