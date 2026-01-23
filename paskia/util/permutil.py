"""Minimal permission helpers with '*' wildcard support (no DB expansion)."""

from collections.abc import Sequence
from fnmatch import fnmatchcase

from paskia import db
from paskia.util.hostutil import normalize_host

__all__ = ["has_any", "has_all", "session_context"]


def _match(perms: set[str], patterns: Sequence[str]):
    return (
        any(fnmatchcase(p, pat) for p in perms) if "*" in pat else pat in perms
        for pat in patterns
    )


def _get_effective_scopes(ctx) -> set[str]:
    """Get effective permission scopes from context.

    Returns scopes from ctx.permissions (filtered by org) if available,
    otherwise falls back to ctx.role.permissions for backwards compatibility.
    """
    if ctx.permissions:
        return {p.scope for p in ctx.permissions}
    # Fallback for contexts without effective permissions computed
    return set(ctx.role.permissions or [])


def has_any(ctx, patterns: Sequence[str]) -> bool:
    return any(_match(_get_effective_scopes(ctx), patterns)) if ctx else False


def has_all(ctx, patterns: Sequence[str]) -> bool:
    return all(_match(_get_effective_scopes(ctx), patterns)) if ctx else False


async def session_context(auth: str | None, host: str | None = None):
    if not auth:
        return None
    normalized_host = normalize_host(host) if host else None
    return db.get_session_context(auth, normalized_host)
