"""Minimal permission helpers with '*' wildcard support (no DB expansion)."""

from collections.abc import Sequence
from fnmatch import fnmatchcase

from paskia import db
from paskia.util.hostutil import normalize_host
from paskia.util.tokens import session_key

__all__ = ["has_any", "has_all", "session_context"]


def _match(perms: set[str], patterns: Sequence[str]):
    return (
        any(fnmatchcase(p, pat) for p in perms) if "*" in pat else pat in perms
        for pat in patterns
    )


def has_any(ctx, patterns: Sequence[str]) -> bool:
    return any(_match(ctx.role.permissions, patterns)) if ctx else False


def has_all(ctx, patterns: Sequence[str]) -> bool:
    return all(_match(ctx.role.permissions, patterns)) if ctx else False


async def session_context(auth: str | None, host: str | None = None):
    if not auth:
        return None
    normalized_host = normalize_host(host) if host else None
    return await db.get_session_context(session_key(auth), normalized_host)
