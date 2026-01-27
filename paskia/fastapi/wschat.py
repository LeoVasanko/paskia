"""
WebSocket chat functions for WebAuthn registration and authentication flows.
"""

from uuid import UUID

from fastapi import WebSocket

from paskia import db
from paskia.db import Credential
from paskia.globals import passkey


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
    origin: str,
    credential_ids: list[bytes] | None = None,
) -> Credential:
    """Run WebAuthn authentication flow and return the verified credential."""
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

    passkey.instance.auth_verify(authcred, challenge, cred, origin)
    return cred
