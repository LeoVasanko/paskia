import logging

from fastapi import Cookie, HTTPException, Request
from fastapi.responses import RedirectResponse

from ..db import db
from ..util import passphrase, tokens
from . import session


def register_reset_routes(app):
    """Register all device addition/reset routes on the FastAPI app."""

    @app.post("/auth/create-link")
    async def api_create_link(request: Request, auth=Cookie(None)):
        """Create a device addition link for the authenticated user."""
        try:
            # Require authentication
            s = await session.get_session(auth)

            # Generate a human-readable token
            token = passphrase.generate()  # e.g., "cross.rotate.yin.note.evoke"
            await db.instance.create_session(
                user_uuid=s.user_uuid,
                key=tokens.reset_key(token),
                expires=session.expires(),
                info=session.infodict(request, "device addition"),
            )

            # Generate the device addition link with pretty URL
            path = request.url.path.removesuffix("create-link") + token
            url = f"{request.headers['origin']}{path}"

            return {
                "status": "success",
                "message": "Registration link generated successfully",
                "url": url,
                "expires": session.expires().isoformat(),
            }

        except ValueError:
            return {"error": "Authentication required"}
        except Exception as e:
            return {"error": f"Failed to create registration link: {str(e)}"}

    @app.get("/auth/{reset_token}")
    async def reset_authentication(
        request: Request,
        reset_token: str,
    ):
        """Verifies the token and redirects to auth app for credential registration."""
        # This route should only match to exact passphrases
        print(f"Reset handler called with url: {request.url.path}")
        if not passphrase.is_well_formed(reset_token):
            raise HTTPException(status_code=404)
        try:
            # Get session token to validate it exists and get user_id
            key = tokens.reset_key(reset_token)
            sess = await db.instance.get_session(key)
            if not sess:
                raise ValueError("Invalid or expired registration token")

            response = RedirectResponse(url="/auth/", status_code=303)
            session.set_session_cookie(response, reset_token)
            return response

        except Exception as e:
            # On any error, redirect to auth app
            if isinstance(e, ValueError):
                msg = str(e)
            else:
                logging.exception("Internal Server Error in reset_authentication")
                msg = "Internal Server Error"
            return RedirectResponse(url=f"/auth/#{msg}", status_code=303)
