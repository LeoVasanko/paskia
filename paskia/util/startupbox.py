"""Startup configuration box formatting utilities."""

import os

BOX_WIDTH = 60  # Inner width (excluding box chars)


def line(text: str = "") -> str:
    """Format a line inside the box with proper padding, truncating if needed."""
    if len(text) > BOX_WIDTH:
        text = text[: BOX_WIDTH - 1] + "…"
    return f"┃ {text:<{BOX_WIDTH}} ┃\n"


def top() -> str:
    return "┏" + "━" * (BOX_WIDTH + 2) + "┓\n"


def bottom() -> str:
    return "┗" + "━" * (BOX_WIDTH + 2) + "┛\n"


def print_startup_config(passkey_instance, args, host, port, uds) -> None:
    """Print server configuration on startup."""
    from sys import stderr

    from paskia._version import __version__

    lines = [top()]
    lines.append(line(" ▄▄▄▄▄"))
    lines.append(line("█     █ Paskia " + __version__))
    lines.append(line("█     █▄▄▄▄▄▄▄▄▄▄▄▄"))
    lines.append(line("█     █▀▀▀▀█▀▀█▀▀█"))
    lines.append(line(" ▀▀▀▀▀"))

    # Format auth host section
    auth_host = getattr(args, "auth_host", None)
    if auth_host:
        lines.append(line(f"Auth Host:      {auth_host}"))

    # Show frontend URL if in dev mode
    devmode = os.environ.get("PASKIA_DEVMODE")
    if devmode:
        lines.append(line(f"Dev Frontend:   {devmode}"))

    # Format listen address with scheme
    if uds:
        listen = f"unix:{uds}"
    elif host:
        listen = f"http://{host}:{port}"
    else:
        listen = f"http://0.0.0.0:{port} + [::]:{port}"
    lines.append(line(f"Backend:        {listen}"))

    # Relying Party line (omit name if same as id)
    rp_id = passkey_instance.rp_id
    rp_name = passkey_instance.rp_name
    if rp_name and rp_name != rp_id:
        lines.append(line(f"Relying Party:  {rp_id}  ({rp_name})"))
    else:
        lines.append(line(f"Relying Party:  {rp_id}"))

    # Format origins section
    allowed = passkey_instance.allowed_origins
    if allowed:
        lines.append(line("Permitted Origins:"))
        for origin in sorted(allowed):
            lines.append(line(f"  - {origin}"))
    else:
        lines.append(line(f"Origin:         {rp_id} and all subdomains allowed"))

    lines.append(bottom())
    stderr.write("".join(lines))
