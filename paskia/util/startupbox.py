"""Startup configuration box formatting utilities."""

import os
import re
from sys import stderr
from typing import TYPE_CHECKING

from paskia._version import __version__

if TYPE_CHECKING:
    from paskia.config import PaskiaConfig

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


def print_startup_config(config: "PaskiaConfig") -> None:
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
            + config.site_url
            + config.site_path
            + r
        )
    )
    lines.append(line(f" {y}▀▀▀▀▀{r}"))

    # Format auth host section
    if config.auth_host:
        lines.append(line(f"Auth Host:      {config.auth_host}"))

    # Show frontend URL if in dev mode
    devmode = os.environ.get("PASKIA_VITE_URL")
    if devmode:
        lines.append(line(f"Dev Frontend:   {devmode}"))

    # Format listen address with scheme
    if config.uds:
        listen = f"unix:{config.uds}"
    elif config.host:
        listen = f"http://{config.host}:{config.port}"
    else:
        listen = f"http://0.0.0.0:{config.port} + [::]:{config.port}"
    lines.append(line(f"Backend:        {listen}"))

    # Relying Party line (omit name if same as id)
    rp_id = config.rp_id
    rp_name = config.rp_name
    if rp_name and rp_name != rp_id:
        lines.append(line(f"Relying Party:  {rp_id}  ({rp_name})"))
    else:
        lines.append(line(f"Relying Party:  {rp_id}"))

    # Format origins section
    allowed = config.origins
    if allowed:
        lines.append(line("Permitted Origins:"))
        for origin in sorted(allowed):
            lines.append(line(f"  - {origin}"))
    else:
        lines.append(line(f"Origin:         {rp_id} and all subdomains allowed"))

    lines.append(bottom())
    stderr.write("".join(lines))
