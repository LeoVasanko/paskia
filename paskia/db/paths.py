"""Filesystem paths for paskia persistence.

The combined database is a single kanta JSONL file at the fixed
CWD-relative path ``paskia.kantadb``. Auxiliary user files (avatars) live
under ``paskia.data/``. The deployment is selected by the current working
directory; there is deliberately no environment override.
"""

from pathlib import Path

DB_FILENAME = "paskia.kantadb"
DATA_DIRNAME = "paskia.data"


def db_file_path() -> Path:
    """Return the combined database file path."""
    return Path(DB_FILENAME)


def data_root_path(create_root: bool = False) -> Path:
    """Return the root directory for auxiliary files (avatars etc.)."""
    root = Path(DATA_DIRNAME)
    if create_root:
        root.mkdir(parents=True, exist_ok=True)
    return root


def users_root_path(create_root: bool = False) -> Path:
    """Return the filesystem root for persisted user files."""
    root = data_root_path(create_root=create_root) / "users"
    if create_root:
        root.mkdir(parents=True, exist_ok=True)
    return root
