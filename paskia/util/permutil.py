"""Minimal permission helpers with '*' wildcard support (no DB expansion)."""

import re
from collections.abc import Sequence
from functools import lru_cache

from paskia.authsession import session_ctx
from paskia.util.hostutil import normalize_host

__all__ = [
    "group_satisfied",
    "has_all",
    "has_all_groups",
    "has_all_scopes",
    "has_all_scopes_groups",
    "has_any",
    "parse_perm_args",
    "session_context",
]

# Characters allowed in a scope pattern within the perm query argument:
# the scope charset (see querysafe) plus the '*' wildcard.
_SCOPE_PATTERN_RE = re.compile(r"^[A-Za-z0-9:._~/*-]+$")


def parse_perm_args(values: Sequence[str]) -> list[tuple[str, ...]]:
    """Parse repeated perm query argument values into groups of alternatives.

    Each value holds space-separated groups; each group holds one or more
    scope patterns separated by '|'. A group is satisfied when any of its
    alternatives matches; all groups must be satisfied (AND semantics).

    Extra spaces around groups (leading, trailing, repeated) are tolerated.
    Anything else out of spec raises ValueError: empty values, empty
    alternatives around '|', characters outside the scope charset and the
    '*' wildcard, stray '+' etc.
    """
    groups: list[tuple[str, ...]] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise ValueError("perm value must not be empty")
        for group in value.split(" "):
            if not group:
                # Tolerate extra spaces from URL formatting
                continue
            alternatives = group.split("|")
            for alt in alternatives:
                if not alt:
                    raise ValueError("empty alternative around '|' in perm argument")
                if not _SCOPE_PATTERN_RE.match(alt):
                    raise ValueError("invalid character in perm scope pattern")
            groups.append(tuple(alternatives))
    return groups


@lru_cache(maxsize=256)
def _pattern_regex(pattern: str) -> re.Pattern:
    """Compile a scope pattern to a regex with filename-like wildcards.

    '*' matches any sequence within a single path segment (it crosses
    neither ':' nor '/'), '**' matches across separators. Partial segments
    may be wildcarded (e.g. 'myapp:re*' or '*:read').
    """
    parts = []
    i = 0
    while i < len(pattern):
        if pattern[i] == "*":
            if pattern[i + 1 : i + 2] == "*":
                parts.append(".*")
                i += 2
            else:
                parts.append("[^:/]*")
                i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(parts))


def _match(perms: set[str], patterns: Sequence[str]):
    return (
        any(_pattern_regex(pat).fullmatch(p) for p in perms)
        if "*" in pat
        else pat in perms
        for pat in patterns
    )


def group_satisfied(perms: set[str], group: Sequence[str]) -> bool:
    """Check that at least one alternative in the group matches."""
    return any(_match(perms, group))


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


def has_all_groups(ctx, groups: Sequence[Sequence[str]]) -> bool:
    """Check that every group has at least one matching alternative."""
    if not ctx:
        return False
    scopes = _get_effective_scopes(ctx)
    return all(group_satisfied(scopes, g) for g in groups)


def has_all_scopes(scopes: set[str], patterns: Sequence[str]) -> bool:
    """Check that a pre-computed scope set satisfies all required patterns."""
    return all(_match(scopes, patterns)) if patterns else True


def has_all_scopes_groups(scopes: set[str], groups: Sequence[Sequence[str]]) -> bool:
    """Check that a pre-computed scope set satisfies every group of alternatives."""
    return all(group_satisfied(scopes, g) for g in groups)


async def session_context(auth: str | None, host: str | None = None):
    if not auth:
        return None
    normalized_host = normalize_host(host) if host else None
    return session_ctx(auth, normalized_host)
