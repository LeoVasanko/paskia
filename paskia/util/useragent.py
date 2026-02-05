from ua_parser import parse


def compact_user_agent(ua: str | None) -> str:
    """Format user agent string into a compact display format.

    Returns empty string for empty/missing user agents.
    Returns original UA for unrecognized ones.
    """
    if not ua or not ua.strip() or ua == "-":
        return ""
    r = parse(ua)
    browser = r.user_agent.family if r.user_agent else None
    ver = r.user_agent.major if r.user_agent else ""
    os_name = r.os.family if r.os else None
    dev = r.device.family if r.device else None
    # If browser is unrecognized, return original UA
    if browser in (None, "Other") and os_name in (None, "Other"):
        return ua
    # Filter out "Other" values
    browser = browser if browser and browser != "Other" else ""
    os_name = os_name if os_name and os_name != "Other" else ""
    # Exclude device if it's "Other" or matches browser family (parser bug)
    if dev in (None, "Other") or dev == browser:
        dev = ""
    # Build compact string, filtering empty parts
    parts = [f"{browser}/{ver}" if browser else "", os_name, dev]
    result = " ".join(p for p in parts if p).strip()
    return result
