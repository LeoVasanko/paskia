"""Small, dependency-free constants shared by CLI and server modules."""

# App-side default; paskia.__main__ keeps its own literal copy because
# fastapi-vue-setup reads DEFAULT_PORT from the CLI module on upgrades.
DEFAULT_PORT = 4401
