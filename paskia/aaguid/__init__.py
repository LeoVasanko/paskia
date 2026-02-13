"""
AAGUID (Authenticator Attestation GUID) management for WebAuthn credentials.

This module provides functionality to:
- Load AAGUID data from JSON file
- Look up authenticator information by AAGUID
- Return only relevant AAGUID data for user credentials
"""

import json
from collections.abc import Iterable
from importlib.resources import files
from uuid import UUID

__ALL__ = ["AAGUID", "filter"]

# Path to the AAGUID JSON file
AAGUID_FILE = files("paskia") / "aaguid" / "combined_aaguid.json"
AAGUID: dict[str, dict] = json.loads(AAGUID_FILE.read_text(encoding="utf-8"))


def filter(aaguids: Iterable[UUID]) -> dict[str, dict]:
    """
    Get AAGUID information only for the provided set of AAGUIDs.

    Args:
        aaguids: Iterable of AAGUIDs (UUIDs) that the user has credentials for

    Returns:
        Dictionary mapping AAGUID string to authenticator information for only
        the AAGUIDs that the user has and that we have data for
    """
    result = {}
    for a in aaguids:
        s = str(a)
        if s in AAGUID:
            info = AAGUID[s].copy()
            # Rename icon_light to icon
            if "icon_light" in info:
                info["icon"] = info.pop("icon_light")
            # If icons are the same, set dark to None to save space
            if info.get("icon") == info.get("icon_dark"):
                info["icon_dark"] = None
            result[s] = info
    return result
