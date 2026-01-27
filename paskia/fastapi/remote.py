"""
Remote authentication WebSocket endpoints.

This module handles cross-device authentication where one device (requesting)
wants to log in and another device (authenticating) provides the passkey.

Endpoints:
- /request: Called by the device wanting to be authenticated
- /pair: Called by the authenticating device to complete the request
"""

import asyncio
from uuid import UUID

import base64url
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from paskia import db, remoteauth
from paskia.authsession import expires
from paskia.fastapi.session import infodict
from paskia.fastapi.wschat import authenticate_chat
from paskia.fastapi.wsutil import validate_origin, websocket_error_handler
from paskia.util import hostutil, passphrase, pow, useragent

# Create a FastAPI subapp for remote auth WebSocket endpoints
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.websocket("/request")
@websocket_error_handler
async def websocket_remote_auth_request(ws: WebSocket):
    """Request authentication from another device.

    This endpoint is called by the device that wants to be authenticated.
    It creates a remote auth request and waits for another device to authenticate.

    Flow:
    1. Client connects
    2. Server sends HARD PoW challenge, client solves and responds
    3. Server creates a 3-word pairing code and sends it with expiry
    4. Server waits for another device to authenticate via /remote-auth/permit
    5. When auth completes, server sends session_token to this client
    6. Client can then use the session token to set a cookie
    7. Connection times out after 5 minutes with explicit timeout message
    """
    origin = validate_origin(ws)
    host = origin.split("://", 1)[1]

    if remoteauth.instance is None:
        raise ValueError("Remote authentication is not available")

    # Track this WebSocket connection for load-based PoW difficulty
    remoteauth.instance.increment_connections()
    try:
        # Send PoW challenge immediately with dynamic difficulty based on load
        challenge = pow.generate_challenge()
        work = remoteauth.instance.get_pow_difficulty()

        await ws.send_json(
            {
                "pow": {
                    "challenge": base64url.enc(challenge),
                    "work": work,
                }
            }
        )

        # Receive client response with PoW solution and action
        response = await ws.receive_json()

        # Verify PoW (required for this endpoint - SECURITY)
        solution_b64 = response.get("pow")
        if not solution_b64:
            raise ValueError("PoW solution required")

        try:
            solution = base64url.dec(solution_b64)
        except Exception:
            raise ValueError("Invalid PoW solution encoding")

        pow.verify_pow(challenge, solution, work)

        # Extract action from the same message
        action = response.get("action", "login")
        if action not in ("login", "register"):
            action = "login"

        metadata = infodict(ws, "remote-auth-request")

        # Create the remote auth request
        pairing_code, expiry = await remoteauth.instance.create_request(
            host=host,
            ip=metadata.get("ip") or "",
            user_agent=metadata.get("user_agent") or "",
            action=action,
        )

        # Send the pairing code to the client
        await ws.send_json(
            {
                "pairing_code": pairing_code,
                "expires": expiry.isoformat().replace("+00:00", "Z"),
            }
        )

        # Set up async notification for completion
        result_event = asyncio.Event()
        result_data: dict = {}

        def on_complete(
            session_token: str | None,
            user_uuid: UUID | None,
            credential_uuid: UUID | None,
            reset_token: str | None,
        ):
            # Check if this was an explicit denial (UUID(int=0) is the signal)
            was_denied = user_uuid is not None and user_uuid == UUID(int=0)
            result_data["session_token"] = session_token
            result_data["user_uuid"] = user_uuid
            result_data["credential_uuid"] = credential_uuid
            result_data["reset_token"] = reset_token
            result_data["was_denied"] = was_denied
            result_event.set()

        await remoteauth.instance.set_notify_callback(pairing_code, on_complete)

        # Set up async notification for action lock
        locked_event = asyncio.Event()
        locked_data: dict = {}

        def on_action_locked(action: str):
            locked_data["action"] = action
            locked_event.set()

        await remoteauth.instance.set_action_locked_callback(
            pairing_code, on_action_locked
        )

        # 5 minute timeout for the entire remote auth flow
        timeout_seconds = 5 * 60

        try:
            # Wait for either:
            # 1. Authentication to complete (result_event set)
            # 2. Action locked (locked_event set)
            # 3. Client to disconnect
            # 4. Client to send a cancel or update_action message
            # 5. Timeout after 5 minutes

            async with asyncio.timeout(timeout_seconds):
                while True:
                    # Use asyncio.wait to handle events and websocket
                    receive_task = asyncio.create_task(ws.receive_json())
                    result_wait_task = asyncio.create_task(result_event.wait())
                    locked_wait_task = asyncio.create_task(locked_event.wait())

                    tasks = [receive_task, result_wait_task]
                    # Only wait for locked event if not already locked
                    if not locked_event.is_set():
                        tasks.append(locked_wait_task)

                    done, pending = await asyncio.wait(
                        tasks,
                        return_when=asyncio.FIRST_COMPLETED,
                    )

                    # Cancel pending tasks
                    for task in pending:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

                    if result_wait_task in done:
                        # Authentication completed (or expired/cancelled/denied)
                        was_denied = result_data.get("was_denied", False)
                        if result_data.get("session_token") or result_data.get(
                            "reset_token"
                        ):
                            response = {
                                "status": "authenticated",
                                "user": str(result_data["user_uuid"]),
                            }
                            if result_data.get("session_token"):
                                response["session_token"] = result_data["session_token"]
                            if result_data.get("reset_token"):
                                response["reset_token"] = result_data["reset_token"]
                            await ws.send_json(response)
                        else:
                            # Check if it was explicitly denied
                            if was_denied:
                                await ws.send_json(
                                    {
                                        "status": "denied",
                                        "detail": "Access denied",
                                    }
                                )
                            else:
                                await ws.send_json(
                                    {
                                        "status": "expired",
                                        "detail": "Remote authentication request expired or was cancelled",
                                    }
                                )
                        return

                    if locked_wait_task in done:
                        # Action was locked by the authenticating device
                        await ws.send_json(
                            {
                                "status": "locked",
                                "action": locked_data.get("action", "login"),
                            }
                        )
                        # Continue waiting for result

                    if receive_task in done:
                        # Client sent a message
                        msg = receive_task.result()
                        if msg.get("action") == "cancel":
                            await remoteauth.instance.cancel_request(pairing_code)
                            await ws.send_json({"status": "cancelled"})
                            return
                        elif msg.get("action") == "update_action":
                            # Update the action (login/register) if not locked
                            new_action = "register" if msg.get("register") else "login"
                            await remoteauth.instance.update_action(
                                pairing_code, new_action
                            )
                        # Ignore other messages

        except TimeoutError:
            # 5 minute timeout reached
            await remoteauth.instance.cancel_request(pairing_code)
            await ws.send_json(
                {
                    "status": "timeout",
                    "detail": "Remote authentication request timed out after 5 minutes",
                }
            )
        except WebSocketDisconnect:
            # Client disconnected, cancel the request and mark as denied
            await remoteauth.instance.cancel_request(pairing_code, denied=True)
        except Exception:
            await remoteauth.instance.cancel_request(pairing_code)
            raise
    finally:
        # Decrement connection count
        remoteauth.instance.decrement_connections()


@app.websocket("/permit")
@websocket_error_handler
async def websocket_remote_auth_permit(ws: WebSocket):
    """Complete a remote authentication request using a 3-word pairing code.

    This endpoint is called from the user's profile on the authenticating device.
    The user enters the pairing code displayed on the requesting device.

    Protocol:
    1. Server sends PoW challenge immediately on connect
    2. Client sends {code: "word.word.word", pow: "<base64>"} for 3-word pairing code
    3. Server validates PoW and code:
       - If invalid code/PoW: {status: 4xx, detail: "...", pow: {challenge, work}}
       - If valid: {status: "found", host: "...", user_agent_pretty: "...", pow: {challenge, work}}
    4. Client can then send {authenticate: true} to start WebAuthn
    5. Server sends {optionsJSON: ...}
    6. Client sends WebAuthn response
    7. Server sends {status: "success", message: "..."}
    """

    origin = validate_origin(ws)

    if remoteauth.instance is None:
        raise ValueError("Remote authentication is not available")

    # Generate initial PoW challenge (always NORMAL for authenticated users)
    challenge = pow.generate_challenge()
    work = pow.NORMAL

    await ws.send_json(
        {
            "pow": {
                "challenge": base64url.enc(challenge),
                "work": work,
            }
        }
    )

    request = None
    explicitly_denied = False

    try:
        while True:
            msg = await ws.receive_json()

            # Handle deny request first (no PoW needed - already validated during lookup)
            if msg.get("deny") and request is not None:
                # Cancel the request and mark it as denied
                explicitly_denied = True
                await remoteauth.instance.cancel_request(request.key, denied=True)
                await ws.send_json(
                    {
                        "status": "denied",
                        "message": "Request denied",
                    }
                )
                break

            # Handle authenticate request (no PoW needed - already validated during lookup)
            if msg.get("authenticate") and request is not None:
                cred = await authenticate_chat(ws, origin)

                # Create a session for the REQUESTING device
                assert cred.uuid is not None

                session_token = None
                reset_token = None

                if request.action == "register":
                    # For registration, create a reset token for device addition

                    token_str = passphrase.generate()
                    expiry = expires()
                    db.create_reset_token(
                        user_uuid=cred.user,
                        passphrase=token_str,
                        expiry=expiry,
                        token_type="device addition",
                    )
                    reset_token = token_str
                    # Also create a session so the device is logged in
                    normalized_host = hostutil.normalize_host(request.host)
                    session_token = db.login(
                        user_uuid=cred.user,
                        credential=cred,
                        host=normalized_host,
                        ip=request.ip,
                        user_agent=request.user_agent,
                        expiry=expires(),
                    )
                else:
                    # Default login action

                    normalized_host = hostutil.normalize_host(request.host)
                    session_token = db.login(
                        user_uuid=cred.user,
                        credential=cred,
                        host=normalized_host,
                        ip=request.ip,
                        user_agent=request.user_agent,
                        expiry=expires(),
                    )

                # Complete the remote auth request (notifies the waiting device)
                completed = await remoteauth.instance.complete_request(
                    token=request.key,
                    session_token=session_token,
                    user_uuid=cred.user,
                    credential_uuid=cred.uuid,
                    reset_token=reset_token,
                )

                if not completed:
                    raise ValueError("Failed to complete remote authentication")

                msg = "Authentication successful."
                if request.action == "register":
                    msg += " The other device can now register a passkey."
                else:
                    msg += " The other device is now logged in."

                await ws.send_json(
                    {
                        "status": "success",
                        "message": msg,
                    }
                )
                break

            # Handle code lookup request - requires PoW validation
            code = msg.get("code", "")

            # Validate PoW for pairing codes
            solution_b64 = msg.get("pow")
            if not solution_b64:
                raise ValueError("PoW solution required")

            try:
                solution = base64url.dec(solution_b64)
            except Exception:
                raise ValueError("Invalid PoW solution encoding")

            try:
                pow.verify_pow(challenge, solution, work)
            except ValueError as e:
                # Invalid PoW - send new challenge
                challenge = pow.generate_challenge()
                await ws.send_json(
                    {
                        "status": 400,
                        "detail": str(e),
                        "pow": {
                            "challenge": base64url.enc(challenge),
                            "work": work,
                        },
                    }
                )
                continue

            if not code:
                raise ValueError("Pairing code required")

            # Look up the remote auth request by pairing code
            request = await remoteauth.instance.get_request(code)

            # Generate new challenge for next request (always NORMAL for authenticated users)
            challenge = pow.generate_challenge()

            if request is None:
                await ws.send_json(
                    {
                        "status": 404,
                        "detail": "Code not found",
                        "pow": {
                            "challenge": base64url.enc(challenge),
                            "work": work,
                        },
                    }
                )
                request = None  # Reset for next attempt
                continue

            # Valid code found - lock the action so it can't be changed anymore
            # This also notifies the requesting device
            locked_action = await remoteauth.instance.lock_action(request.key)
            if locked_action is None:
                # Already locked by another device
                await ws.send_json(
                    {
                        "status": 409,
                        "detail": "This request is already being processed in another window",
                        "pow": {
                            "challenge": base64url.enc(challenge),
                            "work": work,
                        },
                    }
                )
                request = None  # Reset for next attempt
                continue

            request.action = locked_action  # Update local copy with locked value

            # Send device info to the authenticating device
            await ws.send_json(
                {
                    "status": "found",
                    "host": request.host,
                    "user_agent_pretty": useragent.compact_user_agent(
                        request.user_agent
                    ),
                    "client_ip": request.ip,
                    "action": request.action,
                    "pow": {
                        "challenge": base64url.enc(challenge),
                        "work": work,
                    },
                }
            )
    except Exception:
        # If websocket disconnects without explicit denial, unlock the request
        if request and not explicitly_denied:
            # Unlock the request so the code can be used again
            async with remoteauth.instance._lock:
                req = remoteauth.instance._requests.get(request.key)
                if req and req.locked:
                    req.locked = False
        raise
