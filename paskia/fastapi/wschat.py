"""
WebSocket chat functions for WebAuthn registration and authentication flows.
"""

from uuid import UUID

from fastapi import WebSocket

from paskia import db
from paskia.authsession import session_ctx
from paskia.db import Credential, SessionContext
from paskia.domains import current_domain, registry
from paskia.fastapi.session import infodict
from paskia.fastapi.wsutil import validate_origin
from paskia.util import hostutil


async def register_chat(
    ws: WebSocket,
    user_uuid: UUID,
    user_name: str,
    origin: str,
    credential_ids: list[bytes] | None = None,
):
    """Run WebAuthn registration flow and return the verified credential."""
    passkey = current_domain().passkey
    options, challenge = passkey.reg_generate_options(
        user_id=user_uuid,
        user_name=user_name,
        credential_ids=credential_ids,
    )
    await ws.send_json({"optionsJSON": options})
    response = await ws.receive_json()
    return passkey.reg_verify(response, challenge, user_uuid, origin=origin)


async def authenticate_chat(
    ws: WebSocket,
    credential_ids: list[bytes] | None = None,
) -> tuple[Credential, int]:
    """Run WebAuthn authentication flow and return the credential and new sign count.

    Returns:
        tuple of (credential, new_sign_count) where new_sign_count comes from WebAuthn verification
    """
    domain = current_domain()
    passkey = domain.passkey
    origin = validate_origin(ws)
    options, challenge = passkey.auth_generate_options(credential_ids=credential_ids)
    await ws.send_json({"optionsJSON": options})
    authcred = passkey.auth_parse(await ws.receive_json())

    cred = next(
        (
            c
            for c in db.data().credentials.values()
            if c.credential_id == authcred.raw_id and c.rp_id == domain.rp_id
        ),
        None,
    )
    if not cred:
        raise ValueError(f"This passkey is no longer registered with {passkey.rp_name}")

    verification = passkey.auth_verify(authcred, challenge, cred, origin)
    return cred, verification.new_sign_count


async def authenticate_and_login(
    ws: WebSocket,
    auth: str | None = None,
    *,
    session_host: str | None = None,
    session_ip: str | None = None,
    session_user_agent: str | None = None,
) -> tuple[SessionContext, str]:
    """Run WebAuthn authentication flow, create session, and return the session context.

    If auth is provided, restrict authentication to credentials of that session's user.

    Args:
        ws: The WebSocket connection (used for WebAuthn and origin validation)
        auth: Existing session cookie for re-auth credential restriction
        session_host: Override host for the new session (defaults to ws origin);
            must belong to a configured domain
        session_ip: Override IP for the new session (defaults to ws client IP)
        session_user_agent: Override user-agent for the new session (defaults to ws headers)

    Returns:
        Tuple of (SessionContext for the authenticated session, session secret)
    """
    domain = current_domain()
    origin = validate_origin(ws)
    host = origin.split("://", 1)[1]
    normalized_host = hostutil.normalize_host(host)
    if not normalized_host:
        raise ValueError("Host required for session creation")
    metadata = infodict(ws, "auth")

    # Get credential IDs if restricting to a user's credentials
    credential_ids = None
    if auth:
        existing_ctx = session_ctx(auth, host)
        if existing_ctx:
            credential_ids = existing_ctx.user.credential_ids_for(domain.rp_id) or None

    cred, new_sign_count = await authenticate_chat(ws, credential_ids)

    # Use overrides if provided, otherwise use websocket metadata
    login_host = (
        hostutil.normalize_host(session_host)
        if session_host is not None
        else normalized_host
    )
    if not login_host:
        raise ValueError("Host required for session creation")
    if session_host is not None and registry().resolve(login_host) is None:
        raise ValueError(f"Host '{login_host}' does not belong to a configured domain")
    login_ip = session_ip if session_ip is not None else metadata["ip"]
    login_user_agent = (
        session_user_agent if session_user_agent is not None else metadata["user_agent"]
    )

    # Create session and update user/credential; stamp it with the domain of
    # the session's host (in remote flows the connection domain is the
    # approver's, but the session belongs to the requesting device's domain)
    login_domain = registry().resolve(login_host) or domain
    secret = db.login(
        user_uuid=cred.user_uuid,
        credential_uuid=cred.uuid,
        sign_count=new_sign_count,
        host=login_host,
        ip=login_ip,
        user_agent=login_user_agent,
        rp_id=login_domain.rp_id,
    )

    # Fetch and return the full session context (using the same host the session was created with)
    ctx = session_ctx(secret, login_host)
    if not ctx:
        raise ValueError("Failed to create session context")
    return ctx, secret
