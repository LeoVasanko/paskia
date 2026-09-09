"""Startup configuration box formatting utilities."""

from __future__ import annotations

import os
import re
from sys import stderr
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from fastapi_vue.hostutil import parse_endpoints

from paskia._version import __version__
from paskia.domains import auth_host_url, origin_url, partition_origins
from paskia.util import hostutil
from paskia.util.constants import DEFAULT_PORT, DEVMODE
from paskia.util.hostutil import format_endpoint, wildcard_base

if TYPE_CHECKING:
    from paskia.domains import DomainRegistry

BOX_WIDTH = 80  # Maximum inner width (excluding box chars)
URL_COL = 22  # Column where header URLs start (past the logo graphic)

# ANSI color codes
RESET = "\033[0m"
YELLOW = "\033[38;5;184m"  # Bright yellow (6x6x6 cube, r=4 g=4)
BRIGHT_YELLOW = "\033[38;5;226m"  # Brightest yellow (6x6x6 cube)
BRIGHT_WHITE = "\033[1;37m"  # Bold bright white

_TOKENS = re.compile(r"\033\[[0-9;]*m|.")


def _visible_len(text: str) -> int:
    """Calculate visible length of text, ignoring ANSI escape codes."""
    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def _truncate(text: str, width: int) -> str:
    """Cut text to at most `width` visible chars, keeping ANSI codes intact."""
    if _visible_len(text) <= width:
        return text
    out = []
    visible = 0
    for tok in _TOKENS.findall(text):
        if tok.startswith("\033"):
            out.append(tok)
        elif visible < width - 1:
            out.append(tok)
            visible += 1
        else:
            break
    return "".join(out) + "…" + RESET


def line(text: str = "", width: int = BOX_WIDTH) -> str:
    """Format a line inside the box with proper padding, truncating if needed."""
    text = _truncate(text, width)
    padding = width - _visible_len(text)
    return f"┃ {text}{' ' * padding} ┃\n"


def top(width: int = BOX_WIDTH) -> str:
    return "┏" + "━" * (width + 2) + "┓\n"


def bottom(width: int = BOX_WIDTH) -> str:
    return "┗" + "━" * (width + 2) + "┛\n"


def _compact_url(url: str) -> str:
    """Bare host for https URLs; scheme and port kept for plain http."""
    stripped = url.removeprefix("https://")
    if "://" in stripped:
        scheme, rest = stripped.split("://", 1)
        return f"{scheme}://{rest.split('/')[0]}"
    return stripped.split("/")[0]


def _origin_phrase(key: str, rp_id: str) -> str:
    """Compact phrase for one origins-table key."""
    if base := wildcard_base(key):
        if base == rp_id:
            return "all subdomains" if key.startswith("**.") else "subdomains"
        qualifier = "all subdomains of" if key.startswith("**.") else "subdomains of"
        return f"{qualifier} {base}"
    return _compact_url(origin_url(key))


def _covered_by_wildcard(key: str, pattern: str) -> bool:
    """Whether an origins-table key is redundant given a wildcard key.

    Mirrors DomainConfig matching (sansio._allowlisted): a wildcard covers
    hostnames under its base over https (any port), except under localhost
    where any scheme and any port match. Plain http entries outside
    localhost are therefore never covered and stay listed.
    """
    base = wildcard_base(pattern)
    if base is None:
        return False
    # Keys are bare hosts (https:// and '/' stripped by origin_key, port
    # kept) or full origins; urlparse needs a scheme or '//' prefix.
    hostname = urlparse(key if "://" in key else f"//{key}").hostname
    if not hostname:
        return False
    if pattern.startswith("**."):
        matched = hostutil.is_subdomain(hostname, base)
    else:
        # '*.base' covers exactly one subdomain level
        matched = hostname.endswith(f".{base}") and "." not in hostname[
            : -len(base) - 1
        ]
    if not matched:
        return False
    if hostutil.is_subdomain(base, "localhost"):
        return True  # localhost: any scheme, any port
    return "://" not in key or key.startswith("https://")


def _signin_summary(in_domain: list[str], rp_id: str) -> str:
    """Compact summary of a domain's in-domain sign-in sites."""
    # Prune entries already covered by a reported wildcard (e.g. the auth
    # host under '**.{rp-id}'); http origins outside localhost survive.
    wildcards = [k for k in in_domain if wildcard_base(k)]
    keys = [
        k
        for k in in_domain
        if wildcard_base(k) or not any(_covered_by_wildcard(k, w) for w in wildcards)
    ]
    phrases = [_origin_phrase(key, rp_id) for key in sorted(keys)]
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

    # Format listen endpoints (dev mode only uses the first endpoint)
    endpoints = list(parse_endpoints(listen, DEFAULT_PORT))
    if DEVMODE:
        endpoints = endpoints[:1]  # server.run reload=True uses only one
    parts = [format_endpoint(ep) for ep in endpoints]

    # Header URLs: when a vite dev server is configured, its URL (marked
    # "vite dev"); otherwise one per configured auth host (a full origin URL,
    # clickable in terminals). If none are configured, guess one domain
    # (prefer the shortest https rp_id) and link its /auth/ site path.
    # Entries are pre-styled: bold for the URL, plain for any marker.
    vite_url = os.environ.get("PASKIA_VITE_URL") if DEVMODE else None
    if vite_url:
        header_urls = [f"{w}{vite_url}{r} (vite dev)"]
    else:
        header_urls = [
            f"{w}{url}{r}" for d in domains if (url := auth_host_url(d.config))
        ]
        if not header_urls:
            guess = min(
                domains,
                key=lambda d: (
                    not d.site_url.startswith("https://"),
                    len(d.rp_id),
                    d.rp_id,
                ),
            )
            header_urls = [f"{w}{guess.auth_site_url}{r}"]

    rows = []
    # Logo lines 4-5 carry the first two header URLs; further URLs go on
    # blank-gutter lines beneath the graphic, all at the same column.
    logo = [
        f" {b}▄▄▄▄▄{r}",
        f"{b}█{y}     {b}█{r} Paskia {__version__} @ {' '.join(parts)}",
        f"{b}█{y}     {b}█{y}▄▄▄▄▄▄▄▄▄▄▄▄{r}",
        f"{b}█{y}     {b}█{y}▀▀▀▀{b}█{y}▀▀{b}█{y}▀▀{b}█{r}",
        f" {y}▀▀▀▀▀{r}",
    ]
    for i, text in enumerate(logo):
        url = header_urls[i - 3] if 3 <= i < 3 + len(header_urls) else None
        if url is None:
            rows.append(text)
        else:
            pad = " " * max(URL_COL - _visible_len(text), 1)
            rows.append(f"{text}{pad}{url}")
    for url in header_urls[2:]:
        rows.append(f"{' ' * URL_COL}{url}")

    for domain in domains:
        # One compact line per domain; overlong lines are capped at render.
        rp_name = domain.rp_name
        suffix = f" ({rp_name})" if rp_name and rp_name != domain.rp_id else ""
        head = f"{w}{domain.rp_id}{r}{suffix}"
        if not domain.config.origins:
            rows.append(f"{head} — no sign-in sites")
            continue
        in_domain, related = partition_origins(domain.rp_id, domain.config.origins)
        parts = []
        if in_domain:
            parts.append(_signin_summary(in_domain, domain.rp_id))
        parts.extend(_compact_url(origin_url(k)) for k in sorted(related))
        # "with" implies the rp_id itself may sign in (exact key or a full
        # wildcard); otherwise the origins are a mere list, after a colon.
        covers_self = any(
            k == domain.rp_id or k == f"**.{domain.rp_id}" for k in in_domain
        )
        sep = " with " if covers_self else ": "
        rows.append(f"{head}{sep}{' and '.join(parts)}")

    # Size the box to the widest row, capped at BOX_WIDTH.
    width = min(BOX_WIDTH, max(_visible_len(t) for t in rows))
    out = [top(width)]
    out.extend(line(text, width) for text in rows)
    out.append(bottom(width))
    stderr.write("".join(out))
