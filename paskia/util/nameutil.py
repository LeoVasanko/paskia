"""Name and username utilities."""

import re
import unicodedata


def slugify_name(name: str) -> str:
    """Convert display name to slug-compatible username.

    Uses dots as separators, preserves existing dots and dashes.
    Strips trailing parenthesized content and other unwanted punctuation.

    Examples:
        'John Doe' → 'john.doe'
        'María José García' → 'maria.jose.garcia'
        'Jean-Pierre' → 'jean-pierre'
        'John.Doe' → 'john.doe'
        'John Doe (Admin)' → 'john.doe'
        '  Multiple   Spaces  ' → 'multiple.spaces'

    Returns empty string for empty/whitespace-only input.
    """
    if not name:
        return ""
    # Strip trailing parenthesized content (e.g., " (Admin)")
    name = re.sub(r"\s*\([^)]*\)\s*$", "", name)
    # Normalize unicode → ASCII equivalent (é → e, ñ → n)
    name = unicodedata.normalize("NFKD", name)
    name = name.encode("ascii", "ignore").decode("ascii")
    # Lowercase
    name = name.lower()
    # Replace non-alphanumeric (except . and -) with dots
    name = re.sub(r"[^a-z0-9.-]+", ".", name)
    # Collapse multiple dots
    name = re.sub(r"\.+", ".", name)
    # Strip leading/trailing dots
    return name.strip(".")
