"""Startup configuration box formatting utilities."""

from __future__ import annotations

import os
import re
from sys import stderr
from typing import TYPE_CHECKING

from fastapi_vue.hostutil import parse_endpoints

from paskia._version import __version__
from paskia.util.constants import DEFAULT_PORT, DEVMODE
from paskia.util.hostutil import format_endpoint

if TYPE_CHECKING:
    from paskia.domains import DomainRegistry

from paskia.db.structs import OriginEntry
from paskia.domains import is_related_key, origin_url

BOX_WIDTH = 60  # Inner width (excluding box chars)

# ANSI color codes
RESET = "\033[0m"
YELLOW = "\033[38;5;184m"  # Bright yellow (6x6x6 cube, r=4 g=4)
BRIGHT_YELLOW = "\033[38;5;226m"  # Brightest yellow (6x6x6 cube)
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


def print_startup_config(
    registry: DomainRegistry, listen: list[str] | None = None
) -> None:
    """Print server configuration on startup (one section per domain)."""
    # Key graphic with yellow shading (bright for highlights, dark for body)
    y = YELLOW  # Bright golden yellow for main body
    b = BRIGHT_YELLOW  # Brightest yellow for highlights/edges
    w = BRIGHT_WHITE  # Bold white for URL
    r = RESET

    domains = sorted(registry.domains, key=lambda d: d.rp_id)

    lines = [top()]
    lines.append(line(f" {b}▄▄▄▄▄{r}"))
    lines.append(line(f"{b}█{y}     {b}█{r} Paskia " + __version__))
    lines.append(line(f"{b}█{y}     {b}█{y}▄▄▄▄▄▄▄▄▄▄▄▄{r}"))
    lines.append(
        line(
            f"{b}█{y}     {b}█{y}▀▀▀▀{b}█{y}▀▀{b}█{y}▀▀{b}█{r}    {w}"
            + domains[0].site_url
            + domains[0].site_path
            + r
        )
    )
    lines.append(line(f" {y}▀▀▀▀▀{r}"))

    # Show frontend URL if in dev mode
    if DEVMODE:
        lines.append(line(f"Dev Frontend:   {os.environ.get('PASKIA_VITE_URL')}"))

    # Format listen endpoints (dev mode only uses the first endpoint)

    endpoints = list(parse_endpoints(listen, DEFAULT_PORT))
    if DEVMODE:
        endpoints = endpoints[:1]  # server.run reload=True uses only one
    parts = [format_endpoint(ep) for ep in endpoints]
    lines.append(line(f"Backend:        {' '.join(parts)}"))

    for domain in domains:
        # Domain line (omit name if same as id)
        rp_name = domain.rp_name
        suffix = f" ({rp_name})" if rp_name and rp_name != domain.rp_id else ""
        header = "Domain:         " if len(domains) > 1 else "Relying Party:  "
        lines.append(line(f"{header}{domain.rp_id}{suffix}"))
        if len(domains) > 1:
            lines.append(line(f"  URL:          {domain.site_url}{domain.site_path}"))
        for key, props in sorted(domain.config.origins.items()):
            marker = (
                " (auth host)"
                if isinstance(props, OriginEntry) and props.auth_host
                else ""
            )
            label = "Related:" if is_related_key(domain.rp_id, key) else "Origin:"
            lines.append(line(f"  {label:<14}{origin_url(key)}{marker}"))
        if not domain.config.origins:
            lines.append(line("  Origins:      (none configured)"))

    lines.append(bottom())
    stderr.write("".join(lines))
