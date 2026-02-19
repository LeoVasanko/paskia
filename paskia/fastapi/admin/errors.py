"""Shared exception handlers for admin sub-apps."""

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from paskia.fastapi import authz


def install_error_handlers(app: FastAPI) -> None:
    """Register standard exception handlers on *app*."""

    @app.exception_handler(ValueError)
    async def value_error_handler(_request, exc: ValueError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @app.exception_handler(authz.AuthException)
    async def auth_exception_handler(_request, exc: authz.AuthException):
        return JSONResponse(
            status_code=exc.status_code,
            content=await authz.auth_error_content(exc),
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(_request, exc: Exception):  # pragma: no cover
        logging.exception("Unhandled exception in admin app")
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )
