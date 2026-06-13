"""Small, dependency-free constants shared by CLI and server modules."""

import os

DEFAULT_PORT = 4401
DEVMODE = os.getenv("PASKIA_DEV") == "1"
