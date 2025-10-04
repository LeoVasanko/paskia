import user_agents


def compact_user_agent(ua: str | None) -> str:
    if not ua:
        return "-"
    u = user_agents.parse(ua)
    ver = u.browser.version_string.split(".")[0]
    dev = u.device.family if u.device.family not in ["Other", "Mac"] else ""
    return f"{u.browser.family}/{ver} {u.os.family} {dev}".strip()
