"""
Shared WebSocket utilities for FastAPI endpoints.
"""

import logging
import time
from functools import wraps

import base64url
from fastapi import WebSocket, WebSocketDisconnect
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from paskia.fastapi import authz
from paskia.fastapi.logging import log_ws_close, log_ws_open
from paskia.globals import passkey
from paskia.util import pow


def websocket_error_handler(func):
    """Decorator for WebSocket endpoints that handles common errors."""

    @wraps(func)
    async def wrapper(ws: WebSocket, *args, **kwargs):
        client = ws.client.host if ws.client else "-"
        host = ws.headers.get("host", "-")
        path = ws.url.path

        start = time.perf_counter()
        ws_id = log_ws_open(client, host, path)
        close_code = None

        try:
            await ws.accept()
            return await func(ws, *args, **kwargs)
        except WebSocketDisconnect as e:
            close_code = e.code
        except authz.AuthException as e:
            await ws.send_json(
                {
                    "status": e.status_code,
                    **(await authz.auth_error_content(e)),
                }
            )
        except (ValueError, InvalidAuthenticationResponse) as e:
            await ws.send_json({"status": 401, "detail": str(e)})
        except Exception:
            logging.exception("Internal Server Error")
            await ws.send_json({"status": 500, "detail": "Internal Server Error"})
        finally:
            duration_ms = (time.perf_counter() - start) * 1000
            log_ws_close(client, ws_id, close_code, duration_ms)

    return wrapper


async def require_pow(ws: WebSocket, work: int | None = None) -> None:
    """Send a PoW challenge and verify the client's solution.

    Sends: {"pow": {"challenge": "<base64>", "work": 10}}
    Expects: {"pow": "<base64-solution>"}

    Args:
        ws: WebSocket connection
        work: PoW difficulty level (default: pow.DEFAULT_WORK)

    Raises:
        ValueError: If the PoW solution is invalid
    """
    challenge = pow.generate_challenge()
    if work is None:
        work = pow.DEFAULT_WORK

    await ws.send_json(
        {
            "pow": {
                "challenge": base64url.enc(challenge),
                "work": work,
            }
        }
    )

    response = await ws.receive_json()
    solution_b64 = response.get("pow")
    if not solution_b64:
        raise ValueError("PoW solution required")

    try:
        solution = base64url.dec(solution_b64)
    except Exception:
        raise ValueError("Invalid PoW solution encoding")

    pow.verify_pow(challenge, solution, work)


def validate_origin(ws: WebSocket) -> str:
    """Extract and validate origin from WebSocket request headers.

    Raises:
        ValueError: If origin header is missing or not in allowed list
    """
    origin = ws.headers.get("origin")
    if not origin:
        raise ValueError("Origin header is required for WebSocket connections")
    return passkey.instance.validate_origin(origin)
