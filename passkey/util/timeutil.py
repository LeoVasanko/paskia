"""Utility functions for parsing time durations."""

import re
from datetime import timedelta


def parse_duration(duration_str: str) -> timedelta:
    """Parse a duration string into a timedelta.

    Supports units: s, m, min, h, d
    Examples: "30s", "5m", "5min", "2h", "1d"

    Args:
        duration_str: A string like "30s", "5m", "2h"

    Returns:
        A timedelta object

    Raises:
        ValueError: If the format is invalid
    """
    duration_str = duration_str.strip().lower()

    # Pattern matches: number + unit
    # Units: s (seconds), m/min (minutes), h (hours), d (days)
    pattern = r"^(\d+(?:\.\d+)?)(s|m|min|h|d)$"
    match = re.match(pattern, duration_str)

    if not match:
        raise ValueError(
            f"Invalid duration format: '{duration_str}'. "
            "Expected format like '30s', '5m', '5min', '2h', or '1d'"
        )

    value = float(match.group(1))
    unit = match.group(2)

    if unit == "s":
        return timedelta(seconds=value)
    elif unit in ("m", "min"):
        return timedelta(minutes=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "d":
        return timedelta(days=value)
    else:
        raise ValueError(f"Unsupported time unit: {unit}")
