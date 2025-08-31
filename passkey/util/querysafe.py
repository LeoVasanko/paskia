import re

_SAFE_RE = re.compile(r"^[A-Za-z0-9:._~-]+$")


def assert_safe(value: str, *, field: str = "value") -> None:
    if not isinstance(value, str) or not value or not _SAFE_RE.match(value):
        raise ValueError(f"{field} must match ^[A-Za-z0-9:._~-]+$")

__all__ = ["assert_safe"]
