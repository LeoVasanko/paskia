"""Startup configuration box formatting utilities."""

from __future__ import annotations

import os
import re
from sys import stderr
from typing import TYPE_CHECKING

from fastapi_vue.hostutil import parse_endpoints

from paskia._version import __version__
from paskia.domains import auth_host_url, origin_url, partition_origins
from paskia.util.constants import DEFAULT_PORT, DEVMODE
from paskia.util.hostutil import format_endpoint, wildcard_base

if TYPE_CHECKING:
    from paskia.domains import DomainRegistry

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


def _signin_summary(in_domain: list[str]) -> str:
    """One-line summary of a domain's in-domain sign-in sites."""
    phrases = []
    for key in sorted(in_domain):
        if base := wildcard_base(key):
            phrase = (
                f"{base} and all subdomains"
                if key.startswith("**.")
                else f"subdomains of {base}"
            )
        else:
            phrase = origin_url(key)
        phrases.append(phrase)
    if len(phrases) > 2:
        n = len(phrases) - 1
        return f"{phrases[0]}, +{n} site{'s' if n > 1 else ''}"
    return ", ".join(phrases)


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
            + domains[0].auth_site_url
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

    multi = len(domains) > 1
    for domain in domains:
        # Domain line (omit name if same as id); the rows beneath it belong
        # to the domain by position, so they carry no labels of their own.
        rp_name = domain.rp_name
        suffix = f" ({rp_name})" if rp_name and rp_name != domain.rp_id else ""
        lines.append(line(f"Domain:         {domain.rp_id}{suffix}"))
        if multi:
            lines.append(line(f"  {domain.auth_site_url}"))
        in_domain, related = partition_origins(domain.rp_id, domain.config.origins)
        # The auth host is already presented as the domain's URL, so it is
        # not counted among the sign-in sites.
        auth_url = auth_host_url(domain.config)
        in_domain = [k for k in in_domain if origin_url(k) != auth_url]
        if not domain.config.origins:
            lines.append(line("  (none — no site may sign in)"))
        elif in_domain:
            lines.append(line(f"  {_signin_summary(in_domain)}"))
        # Related origins are few (capped) and genuinely surprising cross-domain
        # info, so they are always listed in full.
        for key in sorted(related):
            lines.append(line(f"  {origin_url(key)}"))

    lines.append(bottom())
    stderr.write("".join(lines))
