"""
Database change logging with pretty-printed diffs.

Provides a logger for JSONL database changes that formats diffs
in a human-readable path.notation style with color coding.
"""

import logging
import re
import sys
from typing import Any

logger = logging.getLogger("paskia.db")

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
_REPLACE = "\033[0;33m"  # Yellow for replacements
_DELETE = "\033[0;31m"  # Red for deletions
_ADD = "\033[0;32m"  # Green for additions
_ACTION = "\033[1;34m"  # Bold blue for action name
_USER = "\033[0;34m"  # Blue for user display


def _use_color() -> bool:
    """Check if we should use color output."""
    return sys.stderr.isatty()


def _format_value(value: Any, use_color: bool, max_len: int = 60) -> str:
    """Format a value for display, truncating if needed."""
    if value is None:
        return "null"

    if isinstance(value, bool):
        return "true" if value else "false"

    if isinstance(value, (int, float)):
        return str(value)

    if isinstance(value, str):
        # Filter out control characters and bidirectional overrides
        value = _UNSAFE_CHARS.sub("", value)
        # Truncate long strings
        if len(value) > max_len:
            return value[: max_len - 3] + "..."
        return value

    if isinstance(value, dict):
        if not value:
            return "{}"
        # For small dicts, show inline
        if len(value) == 1:
            k, v = next(iter(value.items()))
            return "{" + f"{k}: {_format_value(v, use_color, max_len=30)}" + "}"
        return f"{{...{len(value)} keys}}"

    if isinstance(value, list):
        if not value:
            return "[]"
        if len(value) == 1:
            return "[" + _format_value(value[0], use_color, max_len=30) + "]"
        return f"[...{len(value)} items]"

    # Fallback for other types
    text = str(value)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def _format_path(path: list[str], use_color: bool) -> str:
    """Format a path as dot notation with prefix in dark grey, final in default."""
    if not path:
        return ""
    if not use_color:
        return ".".join(path)
    if len(path) == 1:
        return f"{_PATH_FINAL}{path[0]}{_RESET}"
    prefix = ".".join(path[:-1])
    final = path[-1]
    return f"{_PATH_PREFIX}{prefix}.{_RESET}{_PATH_FINAL}{final}{_RESET}"


def _collect_changes(
    diff: dict, path: list[str], changes: list[tuple[str, list[str], Any, Any | None]]
) -> None:
    """
    Recursively collect changes from a diff into a flat list.

    Each change is a tuple of (change_type, path, new_value, old_value).
    change_type is one of: 'set', 'replace', 'delete'
    """
    if not isinstance(diff, dict):
        # Leaf value - this is a set operation
        changes.append(("set", path, diff, None))
        return

    for key, value in diff.items():
        if key == "$delete":
            # $delete contains a list of keys to delete
            if isinstance(value, list):
                for deleted_key in value:
                    changes.append(("delete", path + [str(deleted_key)], None, None))
            else:
                changes.append(("delete", path + [str(value)], None, None))

        elif key == "$replace":
            # $replace contains the new value for this path
            if isinstance(value, dict):
                # Replacing with a dict - show each key as a replacement
                for rkey, rval in value.items():
                    changes.append(("replace", path + [str(rkey)], rval, None))
                if not value:
                    # Empty replacement - clearing the collection
                    changes.append(("replace", path, {}, None))
            else:
                changes.append(("replace", path, value, None))

        elif key.startswith("$"):
            # Other special operations (future-proofing)
            changes.append(("set", path, {key: value}, None))

        else:
            # Regular nested key
            _collect_changes(value, path + [str(key)], changes)


def _format_change_line(
    change_type: str, path: list[str], value: Any, use_color: bool
) -> str:
    """Format a single change as a one-line string."""
    path_str = _format_path(path, use_color)
    value_str = _format_value(value, use_color)

    if change_type == "delete":
        if use_color:
            return f"  ❌  {path_str}"
        return f"  - {path_str}"

    if change_type == "replace":
        if use_color:
            return f"  {_REPLACE}⟳{_RESET} {path_str} {_DIM}={_RESET} {value_str}"
        return f"  ~ {path_str} = {value_str}"

    # Default: set/add
    if use_color:
        return f"  {_ADD}+{_RESET} {path_str} {_DIM}={_RESET} {value_str}"
    return f"  + {path_str} = {value_str}"


def format_diff(diff: dict) -> list[str]:
    """
    Format a JSON diff as human-readable lines.

    Returns a list of formatted lines (without newlines).
    Single changes return one line, multiple changes return multiple lines.
    """
    use_color = _use_color()
    changes: list[tuple[str, list[str], Any, Any | None]] = []
    _collect_changes(diff, [], changes)

    if not changes:
        return []

    # Format each change
    lines = []
    for change_type, path, value, _ in changes:
        lines.append(_format_change_line(change_type, path, value, use_color))

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


def log_change(action: str, diff: dict, user_display: str | None = None) -> None:
    """
    Log a database change with pretty-printed diff.

    Args:
        action: The action name (e.g., "login", "admin:delete_user")
        diff: The JSON diff dict
        user_display: Optional display name of the user who performed the action
    """
    header = format_action_header(action, user_display)
    diff_lines = format_diff(diff)

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
