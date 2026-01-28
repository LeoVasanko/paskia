"""FastAPI response utilities for msgspec.Struct serialization."""

import msgspec
from fastapi import Response


class MsgspecResponse(Response):
    """Response that uses msgspec for JSON encoding.

    Use this for returning msgspec.Struct, dict, or list with proper serialization.
    """

    media_type = "application/json"

    def __init__(
        self,
        content: msgspec.Struct | dict | list,
        status_code: int = 200,
        headers: dict | None = None,
    ):
        body = msgspec.json.encode(content)
        super().__init__(content=body, status_code=status_code, headers=headers)
