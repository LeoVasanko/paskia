"""
JSONL read-only loader using kanta.
"""

import logging
from pathlib import Path

import msgspec
from kanta import replay as replay_jsonl
from kanta.migrate import MigrationRegistry

from paskia.db.migrations import MigrationCtx
from paskia.db.structs import DB, Config

_logger = logging.getLogger(__name__)


def load_readonly(db_path: str, *, rp_id: str = "localhost") -> DB:
    """Replay JSONL and apply migrations to produce a DB, without writing anything.

    This is suitable for reading settings before the server starts.
    Migrations are applied in-memory only; nothing is queued or flushed.
    """
    path = Path(db_path)
    if not path.exists():
        return DB(config=Config(rp_id=rp_id))

    try:
        content = path.read_bytes()
        rr = replay_jsonl(content)
        data_dict = rr.state
        version = rr.version

        if not data_dict:
            return DB(config=Config(rp_id=rp_id))

        # Apply migrations in-memory (no persistence)
        registry = MigrationRegistry.from_module("paskia.db.migrations")
        version = registry.apply(
            data_dict, version, MigrationCtx(rp_id=rp_id), silent=True
        )

        # Decode to msgspec struct
        return msgspec.json.decode(msgspec.json.encode(data_dict), type=DB)
    except OSError as e:
        _logger.exception("Failed to load database")
        raise SystemExit(f"{e}")
    except (ValueError, msgspec.DecodeError) as e:
        raise SystemExit(f"{e}")
    except Exception as e:
        _logger.exception("Unexpected error loading database")
        raise SystemExit(f"{e}")
