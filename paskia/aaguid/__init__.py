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

__ALL__ = ["AAGUID", "filter"]

# Path to the AAGUID JSON file
AAGUID_FILE = files("paskia") / "aaguid" / "combined_aaguid.json"
AAGUID: dict[str, dict] = json.loads(AAGUID_FILE.read_text(encoding="utf-8"))


def filter(aaguids: Iterable[str]) -> dict[str, dict]:
    """
    Get AAGUID information only for the provided set of AAGUIDs.

    Args:
        aaguids: Set of AAGUID strings that the user has credentials for

    Returns:
        Dictionary mapping AAGUID to authenticator information for only
        the AAGUIDs that the user has and that we have data for
    """
    return {aaguid: AAGUID[aaguid] for aaguid in aaguids if aaguid in AAGUID}
