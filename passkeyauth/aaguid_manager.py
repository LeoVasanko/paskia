"""
AAGUID (Authenticator Attestation GUID) management for WebAuthn credentials.

This module provides functionality to:
- Load AAGUID data from JSON file
- Look up authenticator information by AAGUID
- Return only relevant AAGUID data for user credentials
"""

import json
from pathlib import Path
from typing import Optional

# Path to the AAGUID JSON file
AAGUID_FILE = Path(__file__).parent / "combined_aaguid.json"


class AAGUIDManager:
    """Manages AAGUID data and lookups."""

    def __init__(self):
        self.aaguid_data: dict[str, dict] = {}
        self.load_aaguid_data()

    def load_aaguid_data(self) -> None:
        """Load AAGUID data from the JSON file."""
        try:
            with open(AAGUID_FILE, encoding="utf-8") as f:
                self.aaguid_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Warning: Could not load AAGUID data: {e}")
            self.aaguid_data = {}

    def get_authenticator_info(self, aaguid: str) -> Optional[dict]:
        """Get authenticator information for a specific AAGUID."""
        return self.aaguid_data.get(aaguid)

    def get_relevant_aaguids(self, aaguids: set[str]) -> dict[str, dict]:
        """
        Get AAGUID information only for the provided set of AAGUIDs.

        Args:
            aaguids: Set of AAGUID strings that the user has credentials for

        Returns:
            Dictionary mapping AAGUID to authenticator information for only
            the AAGUIDs that the user has and that we have data for
        """
        relevant = {}
        for aaguid in aaguids:
            if aaguid in self.aaguid_data:
                relevant[aaguid] = self.aaguid_data[aaguid]
        return relevant


# Global AAGUID manager instance
_aaguid_manager: Optional[AAGUIDManager] = None


def get_aaguid_manager() -> AAGUIDManager:
    """Get the global AAGUID manager instance."""
    global _aaguid_manager
    if _aaguid_manager is None:
        _aaguid_manager = AAGUIDManager()
    return _aaguid_manager
