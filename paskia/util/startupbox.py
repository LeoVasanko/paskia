"""Startup configuration box formatting utilities."""

from __future__ import annotations

import os
import re
from sys import stderr
from typing import TYPE_CHECKING

from fastapi_vue.hostutil import parse_endpoints

from paskia._version import __version__
from paskia.util.hostutil import format_endpoint

if TYPE_CHECKING:
    from paskia.util.runtime import RuntimeConfig

BOX_WIDTH = 60  # Inner width (excluding box chars)

# ANSI color codes
RESET = "\033[0m"
YELLOW = "\033[33m"  # Dark yellow
BRIGHT_YELLOW = "\033[93m"  # Bright yellow
BRIGHT_WHITE = "\033[1;37m"  # Bold bright white


def _visible_len(text: str) -> int:
    """Calculate visible length of text, ignoring ANSI escape codes."""
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def line(text: str = "") -> str:
    """Format a line inside the box with proper padding, truncating if needed."""
    visible = _visible_len(text)
    if visible > BOX_WIDTH:
        text = text[: BOX_WIDTH - 1] + "…"
        visible = BOX_WIDTH
    padding = BOX_WIDTH - visible
    return f"┃ {text}{' ' * padding} ┃\n"


def top() -> str:
    return "┏" + "━" * (BOX_WIDTH + 2) + "┓\n"


def bottom() -> str:
    return "┗" + "━" * (BOX_WIDTH + 2) + "┛\n"


def print_startup_config(runtime: RuntimeConfig) -> None:
    """Print server configuration on startup."""
    # Key graphic with yellow shading (bright for highlights, dark for body)
    y = YELLOW  # Dark yellow for main body
    b = BRIGHT_YELLOW  # Bright yellow for highlights/edges
    w = BRIGHT_WHITE  # Bold white for URL
    r = RESET

    lines = [top()]
    lines.append(line(f" {b}▄▄▄▄▄{r}"))
    lines.append(line(f"{b}█{y}     {b}█{r} Paskia " + __version__))
    lines.append(line(f"{b}█{y}     {b}█{y}▄▄▄▄▄▄▄▄▄▄▄▄{r}"))
    lines.append(
        line(
            f"{b}█{y}     {b}█{y}▀▀▀▀{b}█{y}▀▀{b}█{y}▀▀{b}█{r}    {w}"
            + runtime.site_url
            + runtime.site_path
            + r
        )
    )
    lines.append(line(f" {y}▀▀▀▀▀{r}"))

    # Format auth host section
    if runtime.config.auth_host:
        lines.append(line(f"Auth Host:      {runtime.config.auth_host}"))

    from paskia.__main__ import DEFAULT_PORT as P  # noqa: PLC0415 - circular
    from paskia.__main__ import DEVMODE  # noqa: PLC0415 - circular

    # Show frontend URL if in dev mode
    if DEVMODE:
        lines.append(line(f"Dev Frontend:   {os.environ.get('PASKIA_VITE_URL')}"))

    # Format listen endpoints (dev mode only uses the first endpoint)

    endpoints = list(parse_endpoints(runtime.config.listen, P))
    if DEVMODE:
        endpoints = endpoints[:1]  # server.run reload=True uses only one
    parts = [format_endpoint(ep) for ep in endpoints]
    lines.append(line(f"Backend:        {' '.join(parts)}"))

    # Relying Party line (omit name if same as id)
    rp_id = runtime.config.rp_id
    rp_name = runtime.config.rp_name
    suffix = f" ({rp_name})" if rp_name and rp_name != rp_id else ""
    lines.append(line(f"Relying Party:  {rp_id}{suffix}"))

    # Format origins section
    allowed = runtime.config.origins
    if allowed:
        lines.append(line("Permitted Origins:"))
        for origin in sorted(allowed):
            lines.append(line(f"  - {origin}"))
    else:
        lines.append(line(f"Origin:         {rp_id} and all subdomains allowed"))

    lines.append(bottom())
    stderr.write("".join(lines))
