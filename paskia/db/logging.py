"""
Database change logging with pretty-printed diffs.

Provides a logger for JSONL database changes that formats diffs
in a human-readable path.notation style with color coding.

UUIDs are replaced with display names where available, or the full UUID string
for types without display names.
"""

import logging
import re
import sys
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from paskia.db.structs import DB

logger = logging.getLogger("paskia.db")

# UUID regex pattern (8-4-4-4-12 hex format)
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Pattern to match control characters and bidirectional overrides
_UNSAFE_CHARS = re.compile(
    r"[\x00-\x1f\x7f-\x9f"  # C0 and C1 control characters
    r"\u200e\u200f"  # LRM, RLM
    r"\u202a-\u202e"  # LRE, RLE, PDF, LRO, RLO
    r"\u2066-\u2069"  # LRI, RLI, FSI, PDI
    r"]"
)

# ANSI color codes (matching FastAPI logging style)
_RESET = "\033[0m"
_DIM = "\033[2m"
_PATH_PREFIX = "\033[1;30m"  # Dark grey for path prefix (like host in access log)
_PATH_FINAL = "\033[0m"  # Default for final element (like path in access log)
_DELETE = "\033[1;31m"  # Red for deletions
_ADD = "\033[0;32m"  # Green for additions
_ACTION = "\033[1;34m"  # Bold blue for action name
_USER = "\033[0;34m"  # Blue for user display


def _is_uuid(value: str) -> bool:
    """Check if a string is a UUID."""
    return bool(_UUID_PATTERN.match(value))


def _uuid_suffix(uuid_str: str) -> str:
    """Get the last section of a UUID (after the last hyphen)."""
    return uuid_str.rsplit("-", 1)[-1]


class UuidResolver:
    """Resolve UUIDs to display names or short suffixes.

    Uses the previous state for lookups to show the name before any changes.
    """

    def __init__(self, db: "DB | None" = None, previous: dict | None = None):
        self._db = db
        self._previous = previous

    def resolve(self, uuid_str: str) -> str:
        """Resolve a UUID to its display name or the full UUID string."""
        display = self._get_display_name(uuid_str)
        if display:
            return display
        return uuid_str

    def _get_display_name(self, uuid_str: str) -> str | None:
        """Look up display name for a UUID.

        First checks the previous state (to show names before changes),
        then falls back to the current database.
        """
        # Try previous state first (for showing name before a change)
        name = self._lookup_in_previous(uuid_str)
        if name:
            return name

        # Fall back to current database
        return self._lookup_in_db(uuid_str)

    def _lookup_in_previous(self, uuid_str: str) -> str | None:
        """Look up display name in the previous state dict."""
        if not self._previous:
            return None

        # Check users
        if "users" in self._previous and uuid_str in self._previous["users"]:
            user_data = self._previous["users"][uuid_str]
            if isinstance(user_data, dict) and "display_name" in user_data:
                return user_data["display_name"]

        # Check orgs
        if "orgs" in self._previous and uuid_str in self._previous["orgs"]:
            org_data = self._previous["orgs"][uuid_str]
            if isinstance(org_data, dict) and "display_name" in org_data:
                return org_data["display_name"]

        # Check roles
        if "roles" in self._previous and uuid_str in self._previous["roles"]:
            role_data = self._previous["roles"][uuid_str]
            if isinstance(role_data, dict) and "display_name" in role_data:
                return role_data["display_name"]

        # Check permissions
        if (
            "permissions" in self._previous
            and uuid_str in self._previous["permissions"]
        ):
            perm_data = self._previous["permissions"][uuid_str]
            if isinstance(perm_data, dict) and "display_name" in perm_data:
                return perm_data["display_name"]

        return None

    def _lookup_in_db(self, uuid_str: str) -> str | None:
        """Look up display name in the current database."""
        if not self._db:
            return None

        try:
            uuid_obj = UUID(uuid_str)
        except ValueError:
            return None

        # Check users
        if uuid_obj in self._db.users:
            return self._db.users[uuid_obj].display_name

        # Check orgs
        if uuid_obj in self._db.orgs:
            return self._db.orgs[uuid_obj].display_name

        # Check roles
        if uuid_obj in self._db.roles:
            return self._db.roles[uuid_obj].display_name

        # Check permissions
        if uuid_obj in self._db.permissions:
            return self._db.permissions[uuid_obj].display_name

        return None


def _use_color() -> bool:
    """Check if we should use color output."""
    return sys.stderr.isatty()


def _format_value(
    value: Any,
    use_color: bool,
    max_len: int = 60,
    resolver: UuidResolver | None = None,
) -> str:
    """Format a value for display, truncating if needed.

    If resolver is provided, UUIDs are replaced with display names or short suffixes.
    """
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return str(value)

    if isinstance(value, str):
        # Check if it's a UUID and resolve to display name
        if resolver and _is_uuid(value):
            return resolver.resolve(value)
        # Filter out control characters and bidirectional overrides
        value = _UNSAFE_CHARS.sub("", value)
        # Truncate long strings
        if len(value) > max_len:
            return value[: max_len - 3] + "..."
        return value

    if isinstance(value, dict):
        if not value:
            return "{}"
        # Check if all values are True - render as set-like {key1, key2}
        all_true = all(v is True for v in value.values())
        parts = []
        for k, v in value.items():
            # Replace UUID keys with display names
            key_display = resolver.resolve(k) if resolver and _is_uuid(k) else k
            if all_true:
                parts.append(key_display)
            else:
                val_display = _format_value(v, use_color, max_len=30, resolver=resolver)
                parts.append(f"{key_display}: {val_display}")
        return "{" + ", ".join(parts) + "}"

    if isinstance(value, list):
        if not value:
            return "[]"
        parts = [
            _format_value(v, use_color, max_len=30, resolver=resolver) for v in value
        ]
        return "[" + ", ".join(parts) + "]"

    # Fallback for other types
    text = str(value)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def _format_path(
    path: list[str], use_color: bool, resolver: UuidResolver | None = None
) -> str:
    """Format a path as dot notation with prefix in dark grey, final in default.

    If resolver is provided, UUIDs in the path are replaced with display names.
    """
    if not path:
        return ""

    # Replace UUIDs in path with display names
    if resolver:
        path = [resolver.resolve(p) if _is_uuid(p) else p for p in path]

    if not use_color:
        return ".".join(path)
    if len(path) == 1:
        return f"{_PATH_FINAL}{path[0]}{_RESET}"
    prefix = ".".join(path[:-1])
    final = path[-1]
    return f"{_PATH_PREFIX}{prefix}.{_RESET}{_PATH_FINAL}{final}{_RESET}"


def _get_nested(data: dict | None, path: list[str]) -> Any:
    """Get a nested value from a dict by path, or None if not found."""
    if data is None:
        return None
    current = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _collect_changes(
    diff: dict,
    path: list[str],
    changes: list[tuple[str, list[str], Any]],
    previous: dict | None,
) -> None:
    """
    Recursively collect changes from a diff into a flat list.

    Each change is a tuple of (change_type, path, new_value).
    change_type is one of: 'add', 'update', 'delete'
    """
    if not isinstance(diff, dict):
        # Leaf value - check if it existed before
        existed = _get_nested(previous, path) is not None
        changes.append(("update" if existed else "add", path, diff))
        return

    for key, value in diff.items():
        if key == "$delete":
            # $delete contains a list of keys to delete
            if isinstance(value, list):
                for deleted_key in value:
                    changes.append(("delete", path + [str(deleted_key)], None))
            else:
                changes.append(("delete", path + [str(value)], None))

        elif key == "$replace":
            # $replace replaces the entire collection at this path
            # We need to track what was added and what was deleted
            old_collection = _get_nested(previous, path)
            old_keys = (
                set(old_collection.keys())
                if isinstance(old_collection, dict)
                else set()
            )
            new_keys = set(value.keys()) if isinstance(value, dict) else set()

            # Items that existed before but not in new = deleted
            for deleted_key in old_keys - new_keys:
                changes.append(("delete", path + [str(deleted_key)], None))

            # Items in new collection
            if isinstance(value, dict):
                for rkey, rval in value.items():
                    existed = rkey in old_keys
                    changes.append(
                        ("update" if existed else "add", path + [str(rkey)], rval)
                    )
            elif value or not old_keys:
                # Non-dict replacement or empty replacement with nothing before
                changes.append(
                    ("update" if old_collection is not None else "add", path, value)
                )

        elif key.startswith("$"):
            # Other special operations (future-proofing)
            changes.append(("add", path, {key: value}))

        else:
            # Regular nested key - check if this item existed before
            new_path = path + [str(key)]
            existed = _get_nested(previous, new_path) is not None
            if existed:
                # Item exists - recurse to show specific field changes
                _collect_changes(value, new_path, changes, previous)
            else:
                # New item - record as add with full value, don't recurse
                changes.append(("add", new_path, value))


def _format_change_lines(
    change_type: str,
    path: list[str],
    value: Any,
    use_color: bool,
    resolver: UuidResolver | None = None,
) -> list[str]:
    """Format a single change as one or more lines.

    If resolver is provided, UUIDs are replaced with display names.
    """

    # Helper to format path with UUID replacement
    def fmt_path(p: list[str]) -> list[str]:
        if resolver:
            return [resolver.resolve(x) if _is_uuid(x) else x for x in p]
        return p

    formatted_path = fmt_path(path)

    if change_type == "delete":
        if not use_color:
            return [f"  {'.'.join(formatted_path)} ✗"]
        if len(formatted_path) == 1:
            return [f"  {_DELETE}{formatted_path[0]} ✗{_RESET}"]
        prefix = ".".join(formatted_path[:-1])
        final = formatted_path[-1]
        return [f"  {_PATH_PREFIX}{prefix}.{_RESET}{_DELETE}{final} ✗{_RESET}"]

    if change_type == "add":
        # New item being created - only final element in green
        # For dict values, show children on separate indented lines
        if isinstance(value, dict) and value:
            lines = []
            # First line: path with green final element and grey =
            if not use_color:
                lines.append(f"  {'.'.join(formatted_path)} =")
            elif len(formatted_path) == 1:
                lines.append(f"  {_ADD}{formatted_path[0]}{_RESET} {_DIM}={_RESET}")
            else:
                prefix = ".".join(formatted_path[:-1])
                final = formatted_path[-1]
                lines.append(
                    f"  {_PATH_PREFIX}{prefix}.{_RESET}{_ADD}{final}{_RESET} {_DIM}={_RESET}"
                )
            # Child lines: indented key: value, with aligned values
            # Format keys (may contain UUIDs)
            formatted_items = []
            for k, v in value.items():
                k_display = resolver.resolve(k) if resolver and _is_uuid(k) else k
                v_str = _format_value(v, use_color, resolver=resolver)
                formatted_items.append((k_display, v_str))
            max_key_len = max(len(k) for k, _ in formatted_items)
            field_width = max(max_key_len, 12)  # minimum 12 chars
            for k_display, v_str in formatted_items:
                padding = " " * (field_width - len(k_display))
                if use_color:
                    lines.append(f"    {k_display}{_DIM}:{_RESET}{padding} {v_str}")
                else:
                    lines.append(f"    {k_display}:{padding} {v_str}")
            return lines
        else:
            value_str = _format_value(value, use_color, resolver=resolver)
            if not use_color:
                return [f"  {'.'.join(formatted_path)} = {value_str}"]
            if len(formatted_path) == 1:
                return [
                    f"  {_ADD}{formatted_path[0]}{_RESET} {_DIM}={_RESET} {value_str}"
                ]
            prefix = ".".join(formatted_path[:-1])
            final = formatted_path[-1]
            return [
                f"  {_PATH_PREFIX}{prefix}.{_RESET}{_ADD}{final}{_RESET} {_DIM}={_RESET} {value_str}"
            ]

    # update: Existing item being updated - normal path colors
    value_str = _format_value(value, use_color, resolver=resolver)
    path_str = _format_path(path, use_color, resolver=resolver)
    if use_color:
        return [f"  {path_str} {_DIM}={_RESET} {value_str}"]
    return [f"  {path_str} = {value_str}"]


def format_diff(
    diff: dict, previous: dict | None = None, db: "DB | None" = None
) -> list[str]:
    """
    Format a JSON diff as human-readable lines.

    Args:
        diff: The JSON diff dict
        previous: The previous state dict (for determining add vs update)
        db: Optional database for looking up display names

    Returns a list of formatted lines (without newlines).
    UUIDs are replaced with display names (using previous state for lookups).
    """
    use_color = _use_color()
    changes: list[tuple[str, list[str], Any]] = []
    _collect_changes(diff, [], changes, previous)

    if not changes:
        return []

    # Create resolver for UUID replacement (uses previous state for lookups)
    resolver = UuidResolver(db, previous)

    # Format each change
    lines = []
    for change_type, path, value in changes:
        lines.extend(
            _format_change_lines(change_type, path, value, use_color, resolver)
        )

    return lines


def format_action_header(action: str, user_display: str | None = None) -> str:
    """Format the action header line."""
    use_color = _use_color()

    if use_color:
        action_str = f"{_ACTION}{action}{_RESET}"
        if user_display:
            user_str = f"{_USER}{user_display}{_RESET}"
            return f"{action_str} by {user_str}"
        return action_str
    else:
        if user_display:
            return f"{action} by {user_display}"
        return action


def log_change(
    action: str,
    diff: dict,
    user_display: str | None = None,
    previous: dict | None = None,
    db: "DB | None" = None,
) -> None:
    """
    Log a database change with pretty-printed diff.

    UUIDs are replaced with display names for readability. For types without
    display names, the full UUID string is used.

    Args:
        action: The action name (e.g., "login", "admin:delete_user")
        diff: The JSON diff dict
        user_display: Optional display name of the user who performed the action
        previous: The previous state dict (for determining add vs update)
        db: Optional database for looking up display names
    """
    header = format_action_header(action, user_display)
    diff_lines = format_diff(diff, previous, db)

    if not diff_lines:
        logger.info(header)
        return

    if len(diff_lines) == 1:
        # Single change - combine on one line
        logger.info(f"{header}{diff_lines[0]}")
    else:
        # Multiple changes - header on its own line, then changes
        logger.info(header)
        for line in diff_lines:
            logger.info(line)


def configure_db_logging() -> None:
    """Configure the database logger to output to stderr without prefix."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
