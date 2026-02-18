"""
OIDC Back-Channel Logout notifications.

When sessions are deleted (logout, admin, expiry), this module notifies
any OIDC clients that have a backchannel_logout_uri configured.
"""

import asyncio
import logging
from uuid import UUID

import httpx

from paskia import db
from paskia.util import oidjwt
from paskia.util.hostutil import _load_config

_logger = logging.getLogger(__name__)

# Timeout for back-channel logout requests
_TIMEOUT = httpx.Timeout(10.0, connect=5.0)


def _issuer() -> str:
    """Derive issuer URL from config (same base as discovery document)."""
    cfg = _load_config()
    return cfg.get("site_url", "https://localhost")


def _collect_oidc_sessions(
    session_keys: list[str],
) -> list[tuple[str, str, UUID, UUID | None]]:
    """Collect (backchannel_logout_uri, sid, client_uuid, user_uuid) for OIDC sessions.

    Must be called before the sessions are deleted from the database.
    Returns only sessions whose client has a backchannel_logout_uri configured.
    """
    notifications = []
    data = db.data()
    for key in session_keys:
        session = data.sessions.get(key)
        if not session or session.client_uuid is None:
            continue
        client = data.oidc.clients.get(session.client_uuid)
        if not client or not client.backchannel_logout_uri:
            continue
        sid = session.key
        notifications.append(
            (client.backchannel_logout_uri, sid, session.client_uuid, session.user_uuid)
        )
    return notifications


async def _send_logout_token(
    client: httpx.AsyncClient,
    uri: str,
    token: str,
) -> None:
    """POST a logout_token to a single client endpoint."""
    try:
        resp = await client.post(
            uri,
            data={"logout_token": token},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code == 200:
            _logger.debug("Back-channel logout OK: %s", uri)
        else:
            _logger.warning(
                "Back-channel logout %s returned %d: %s",
                uri,
                resp.status_code,
                resp.text[:200],
            )
    except Exception:
        _logger.warning("Back-channel logout failed: %s", uri, exc_info=True)


async def notify(
    notifications: list[tuple[str, str, UUID, UUID | None]],
) -> None:
    """Send back-channel logout tokens to all collected endpoints.

    Args:
        notifications: list of (backchannel_logout_uri, sid, client_uuid, user_uuid)
            as returned by _collect_oidc_sessions.
    """
    if not notifications:
        return

    issuer = _issuer()
    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        tasks = []
        for uri, sid, client_uuid, user_uuid in notifications:
            token = oidjwt.create_logout_token(
                issuer=issuer,
                audience=str(client_uuid),
                sid=sid,
                sub=user_uuid,
            )
            tasks.append(_send_logout_token(client, uri, token))
        await asyncio.gather(*tasks, return_exceptions=True)


def schedule_notifications(session_keys: list[str]) -> None:
    """Collect OIDC info from sessions (before deletion) and schedule async notifications.

    Must be called BEFORE the sessions are deleted. The actual HTTP requests
    are fire-and-forget via the running event loop.
    """
    notifications = _collect_oidc_sessions(session_keys)
    if not notifications:
        return
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(notify(notifications))
    except RuntimeError:
        _logger.debug("No event loop for back-channel logout notifications")
