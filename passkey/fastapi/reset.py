from pathlib import Path

from fastapi import Cookie, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from ..authsession import expires, get_session
from ..globals import db
from ..globals import passkey as global_passkey
from ..util import passphrase, tokens
from . import session

# Local copy to avoid circular import with mainapp
STATIC_DIR = Path(__file__).parent.parent / "frontend-build"


def register_reset_routes(app):
    """Register all device addition/reset routes on the FastAPI app."""

    @app.post("/auth/create-link")
    async def api_create_link(request: Request, response: Response, auth=Cookie(None)):
        """Create a device addition link for the authenticated user."""
        # Require authentication
        s = await get_session(auth)

        # Generate a human-readable token
        token = passphrase.generate()  # e.g., "cross.rotate.yin.note.evoke"
        await db.instance.create_session(
            user_uuid=s.user_uuid,
            key=tokens.reset_key(token),
            expires=expires(),
            info=session.infodict(request, "device addition"),
        )

        # Generate the device addition link with pretty URL using configured origin
        origin = global_passkey.instance.origin.rstrip("/")
        path = request.url.path.removesuffix("create-link") + token  # /auth/<token>
        url = f"{origin}{path}"

        return {
            "message": "Registration link generated successfully",
            "url": url,
            "expires": expires().isoformat(),
        }

    @app.get("/auth/{reset_token}")
    async def reset_authentication(request: Request, reset_token: str):
        """Validate reset token and redirect with it as query parameter (no cookies).

        After validation we 303 redirect to /auth/?reset=<token>. The frontend will:
        - Read the token from location.search
        - Use it via Authorization header or websocket query param
        - history.replaceState to remove it from the address bar/history
        """
        if not passphrase.is_well_formed(reset_token):
            raise HTTPException(status_code=404)
        origin = global_passkey.instance.origin
        # Do not verify existence/expiry here; frontend + user-info endpoint will handle invalid tokens.
        redirect_url = f"{origin}/auth/?reset={reset_token}"
        return RedirectResponse(url=redirect_url, status_code=303)
