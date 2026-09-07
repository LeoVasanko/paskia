"""
Shared WebSocket utilities for FastAPI endpoints.
"""

import logging
from functools import wraps

from fastapi import WebSocket, WebSocketDisconnect
from webauthn.helpers.exceptions import InvalidAuthenticationResponse

from paskia.domains import current_domain
from paskia.fastapi import authz


def websocket_error_handler(func):
    """Decorator for WebSocket endpoints that handles common errors."""

    @wraps(func)
    async def wrapper(ws: WebSocket, *args, **kwargs):
        try:
            await ws.accept()
            return await func(ws, *args, **kwargs)
        except WebSocketDisconnect:
            pass
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

    return wrapper


def validate_origin(ws: WebSocket) -> str:
    """Extract and validate origin from WebSocket request headers.

    Raises:
        ValueError: If origin header is missing or not allowed in the current domain
    """
    origin = ws.headers.get("origin")
    if not origin:
        raise ValueError("Origin header is required for WebSocket connections")
    return current_domain().passkey.validate_origin(origin)
