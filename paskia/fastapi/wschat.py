"""
WebSocket chat functions for WebAuthn registration and authentication flows.
"""

from uuid import UUID

from fastapi import WebSocket

from paskia import db
from paskia.authsession import expires
from paskia.db import Credential, SessionContext
from paskia.fastapi.session import infodict
from paskia.fastapi.wsutil import validate_origin
from paskia.globals import passkey
from paskia.util import hostutil


async def register_chat(
    ws: WebSocket,
    user_uuid: UUID,
    user_name: str,
    origin: str,
    credential_ids: list[bytes] | None = None,
):
    """Run WebAuthn registration flow and return the verified credential."""
    options, challenge = passkey.instance.reg_generate_options(
        user_id=user_uuid,
        user_name=user_name,
        credential_ids=credential_ids,
    )
    await ws.send_json({"optionsJSON": options})
    response = await ws.receive_json()
    return passkey.instance.reg_verify(response, challenge, user_uuid, origin=origin)


async def authenticate_chat(
    ws: WebSocket,
    credential_ids: list[bytes] | None = None,
) -> tuple[Credential, int]:
    """Run WebAuthn authentication flow and return the credential and new sign count.

    Returns:
        tuple of (credential, new_sign_count) where new_sign_count comes from WebAuthn verification
    """
    origin = validate_origin(ws)
    options, challenge = passkey.instance.auth_generate_options(
        credential_ids=credential_ids
    )
    await ws.send_json({"optionsJSON": options})
    authcred = passkey.instance.auth_parse(await ws.receive_json())

    cred = next(
        (
            c
            for c in db.data().credentials.values()
            if c.credential_id == authcred.raw_id
        ),
        None,
    )
    if not cred:
        raise ValueError(
            f"This passkey is no longer registered with {passkey.instance.rp_name}"
        )

    verification = passkey.instance.auth_verify(authcred, challenge, cred, origin)
    return cred, verification.new_sign_count


async def authenticate_and_login(
    ws: WebSocket,
    auth: str | None = None,
) -> SessionContext:
    """Run WebAuthn authentication flow, create session, and return the session context.

    If auth is provided, restrict authentication to credentials of that session's user.

    Returns:
        SessionContext for the authenticated session
    """
    origin = validate_origin(ws)
    host = origin.split("://", 1)[1]
    normalized_host = hostutil.normalize_host(host)
    if not normalized_host:
        raise ValueError("Host required for session creation")
    hostname = normalized_host.split(":")[0]
    rp_id = passkey.instance.rp_id
    if not (hostname == rp_id or hostname.endswith(f".{rp_id}")):
        raise ValueError(f"Host must be the same as or a subdomain of {rp_id}")
    metadata = infodict(ws, "auth")

    # Get credential IDs if restricting to a user's credentials
    credential_ids = None
    if auth:
        existing_ctx = db.data().session_ctx(auth, host)
        if existing_ctx:
            credential_ids = db.get_user_credential_ids(existing_ctx.user.uuid) or None

    cred, new_sign_count = await authenticate_chat(ws, credential_ids)

    # Create session and update user/credential
    token = db.login(
        user_uuid=cred.user_uuid,
        credential_uuid=cred.uuid,
        sign_count=new_sign_count,
        host=normalized_host,
        ip=metadata["ip"],
        user_agent=metadata["user_agent"],
        expiry=expires(),
    )

    # Fetch and return the full session context
    ctx = db.data().session_ctx(token, normalized_host)
    if not ctx:
        raise ValueError("Failed to create session context")
    return ctx
