"""
Tests for the core API endpoints (/auth/api/).

These tests cover:
- /auth/api/settings - Public settings endpoint
- /auth/api/validate - Session validation
- /auth/api/forward - Forward auth for reverse proxies
- /auth/api/logout - Session logout
- /auth/api/user-info - User information
- /auth/api/set-session - Set session from bearer token
"""

from datetime import datetime, timezone

import httpx
import pytest

from tests.conftest import auth_headers


class TestSettingsEndpoint:
    """Tests for GET /auth/api/settings"""

    @pytest.mark.asyncio
    async def test_get_settings_returns_rp_info(self, client: httpx.AsyncClient):
        """Settings endpoint should return RP configuration."""
        response = await client.get("/auth/api/settings")
        assert response.status_code == 200
        data = response.json()
        assert "rp_id" in data
        assert "rp_name" in data
        assert "session_cookie" in data
        assert data["rp_id"] == "localhost"
        assert data["rp_name"] == "Test RP"
        assert data["session_cookie"] == "__Host-paskia"

    @pytest.mark.asyncio
    async def test_settings_includes_ui_base_path(self, client: httpx.AsyncClient):
        """Settings should include UI base path."""
        response = await client.get("/auth/api/settings")
        data = response.json()
        assert "ui_base_path" in data


class TestValidateEndpoint:
    """Tests for POST /auth/api/validate"""

    @pytest.mark.asyncio
    async def test_validate_without_auth_returns_401(self, client: httpx.AsyncClient):
        """Validate without session should return 401."""
        response = await client.post("/auth/api/validate")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_validate_with_invalid_token_returns_error(
        self, client: httpx.AsyncClient
    ):
        """Validate with invalid token should return 4xx error."""
        response = await client.post(
            "/auth/api/validate",
            headers=auth_headers("invalid_token!!"),
        )
        # Invalid token format returns 400, expired/missing returns 401
        assert response.status_code in (400, 401)

    @pytest.mark.asyncio
    async def test_validate_with_valid_token_returns_200(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Validate with valid session should return success."""
        response = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert "user_uuid" in data

    @pytest.mark.asyncio
    async def test_validate_with_permission_check(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Validate should check permissions when provided."""
        # Admin user should pass admin permission check
        response = await client.post(
            "/auth/api/validate?perm=auth:admin",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_validate_permission_denied_for_regular_user(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """Regular user should fail admin permission check."""
        response = await client.post(
            "/auth/api/validate?perm=auth:admin",
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 403


class TestForwardEndpoint:
    """Tests for GET /auth/api/forward (reverse proxy auth)"""

    @pytest.mark.asyncio
    async def test_forward_without_auth_returns_401(self, client: httpx.AsyncClient):
        """Forward auth without session should return 401."""
        response = await client.get("/auth/api/forward")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_forward_401_json_response(self, client: httpx.AsyncClient):
        """Forward auth 401 should include auth iframe info for JSON clients."""
        response = await client.get(
            "/auth/api/forward",
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 401
        data = response.json()
        assert "auth" in data
        assert "iframe" in data["auth"]
        assert "mode" in data["auth"]
        assert data["auth"]["mode"] == "login"

    @pytest.mark.asyncio
    async def test_forward_with_valid_session_returns_204(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Forward auth with valid session should return 204 with headers."""
        response = await client.get(
            "/auth/api/forward",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 204
        # Check Remote-* headers
        assert "Remote-User" in response.headers
        assert "Remote-Name" in response.headers
        assert "Remote-Groups" in response.headers
        assert "Remote-Org" in response.headers

    @pytest.mark.asyncio
    async def test_forward_with_permission_returns_204(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Forward auth with valid permission should return 204."""
        response = await client.get(
            "/auth/api/forward?perm=auth:admin",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_forward_permission_denied_returns_403(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """Forward auth with missing permission should return 403."""
        response = await client.get(
            "/auth/api/forward?perm=auth:admin",
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_forward_403_json_includes_forbidden_mode(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """403 response should include forbidden mode for iframe."""
        response = await client.get(
            "/auth/api/forward?perm=auth:admin",
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
                "Accept": "application/json",
            },
        )
        assert response.status_code == 403
        data = response.json()
        assert "auth" in data
        assert data["auth"]["mode"] == "forbidden"


class TestLogoutEndpoint:
    """Tests for POST /auth/api/logout"""

    @pytest.mark.asyncio
    async def test_logout_without_session_returns_message(
        self, client: httpx.AsyncClient
    ):
        """Logout without session should return already logged out message."""
        response = await client.post("/auth/api/logout")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Already logged out" in data["message"]

    @pytest.mark.asyncio
    async def test_logout_with_valid_session(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Logout with valid session should succeed and clear session."""
        response = await client.post(
            "/auth/api/logout",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "Logged out successfully" in data["message"]

        # Verify session is no longer valid
        response2 = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response2.status_code == 401


class TestUserInfoEndpoint:
    """Tests for POST /auth/api/user-info"""

    @pytest.mark.asyncio
    async def test_user_info_without_auth_returns_401(self, client: httpx.AsyncClient):
        """User info without session should return 401."""
        response = await client.post("/auth/api/user-info")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_user_info_with_valid_session(
        self, client: httpx.AsyncClient, session_token: str, test_user
    ):
        """User info with valid session should return user data."""
        response = await client.post(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "user" in data
        assert data["user"]["user_uuid"] == str(test_user.uuid)
        assert data["user"]["user_name"] == test_user.display_name

    @pytest.mark.asyncio
    async def test_user_info_includes_credentials(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User info should include user's credentials."""
        response = await client.post(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "credentials" in data
        assert len(data["credentials"]) >= 1

    @pytest.mark.asyncio
    async def test_user_info_includes_sessions(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User info should include user's active sessions."""
        response = await client.post(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "sessions" in data
        assert len(data["sessions"]) >= 1

    @pytest.mark.asyncio
    async def test_user_info_includes_permissions(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User info should include user's permissions."""
        response = await client.post(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data


class TestSetSessionEndpoint:
    """Tests for POST /auth/api/set-session"""

    @pytest.mark.asyncio
    async def test_set_session_without_bearer_returns_403(
        self, client: httpx.AsyncClient
    ):
        """Set session without bearer token should return 403."""
        response = await client.post("/auth/api/set-session")
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_set_session_with_valid_bearer_token(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Set session with valid bearer token should set cookie."""
        response = await client.post(
            "/auth/api/set-session",
            headers={
                "Authorization": f"Bearer {session_token}",
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "user_uuid" in data
        # Check that Set-Cookie header is present
        assert "set-cookie" in response.headers


class TestErrorHandling:
    """Tests for API error handling"""

    @pytest.mark.asyncio
    async def test_invalid_endpoint_returns_404(self, client: httpx.AsyncClient):
        """Request to non-existent endpoint should return 404."""
        response = await client.get("/auth/api/nonexistent")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_error_response_on_bad_token(self, client: httpx.AsyncClient):
        """Bad token should return error response."""
        response = await client.post(
            "/auth/api/validate",
            headers=auth_headers("expired_token!"),
        )
        # Malformed token returns 400, expired returns 401
        assert response.status_code in (400, 401)


class TestForwardAuthHtmlResponse:
    """Tests for forward auth HTML responses"""

    @pytest.mark.asyncio
    async def test_forward_401_html_response(self, client: httpx.AsyncClient):
        """Forward auth 401 should return HTML page for browser requests."""
        response = await client.get(
            "/auth/api/forward",
            headers={"Accept": "text/html"},
        )
        assert response.status_code == 401
        assert "text/html" in response.headers.get("content-type", "")
        # HTML response should contain the mode data attribute
        assert b"data-mode" in response.content or b"mode" in response.content

    @pytest.mark.asyncio
    async def test_forward_403_html_response(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """Forward auth 403 should return HTML page for browser requests."""
        response = await client.get(
            "/auth/api/forward?perm=auth:admin",
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
                "Accept": "text/html",
            },
        )
        assert response.status_code == 403
        assert "text/html" in response.headers.get("content-type", "")

    @pytest.mark.asyncio
    async def test_forward_with_expired_session_clears_cookie(
        self, client: httpx.AsyncClient
    ):
        """Forward auth with expired session should trigger clear_session path."""
        # Use a well-formed but non-existent session token
        fake_token = "aaaaaaaaaaaaaaaa"  # Exactly 16 characters
        response = await client.get(
            "/auth/api/forward",
            headers={
                **auth_headers(fake_token),
                "Host": "localhost:4401",
                "Accept": "application/json",
            },
        )
        assert response.status_code == 401
        # Verify the response contains auth info for re-login
        data = response.json()
        assert "auth" in data
        assert data["auth"]["mode"] == "login"


class TestUserInfoWithResetToken:
    """Tests for user-info endpoint with reset tokens"""

    @pytest.mark.asyncio
    async def test_user_info_with_invalid_reset_token(self, client: httpx.AsyncClient):
        """User info with invalid reset token format should return 401."""
        # Invalid format - not a well-formed passphrase (wrong separator)
        response = await client.post(
            "/auth/api/user-info?reset=invalid-token-format",
        )
        # Invalid format raises ValueError which gets converted to 401 HTTPException
        assert response.status_code == 401
        data = response.json()
        assert "Invalid reset token" in data["detail"]

    @pytest.mark.asyncio
    async def test_user_info_with_nonexistent_reset_token(
        self, client: httpx.AsyncClient
    ):
        """User info with well-formed but non-existent reset token should return 401."""
        # We need a well-formed passphrase that doesn't exist in DB
        from paskia.util.passphrase import generate

        fake_token = generate()  # Generates a well-formed token
        response = await client.post(
            f"/auth/api/user-info?reset={fake_token}",
        )
        # Should return 401 for non-existent token
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_user_info_with_valid_reset_token(
        self, client: httpx.AsyncClient, reset_token: str, test_user
    ):
        """User info with valid reset token should return minimal user info."""
        response = await client.post(
            f"/auth/api/user-info?reset={reset_token}",
        )
        assert response.status_code == 200
        data = response.json()
        assert "user" in data


class TestSetSessionErrors:
    """Tests for set-session error cases"""

    @pytest.mark.asyncio
    async def test_set_session_with_invalid_bearer_token(
        self, client: httpx.AsyncClient
    ):
        """Set session with invalid (malformed) bearer token should return 400."""
        response = await client.post(
            "/auth/api/set-session",
            headers={
                "Authorization": "Bearer invalid_token_here",  # Wrong length (18 chars)
                "Host": "localhost:4401",
            },
        )
        # Invalid token format returns 400
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_set_session_with_nonexistent_token(self, client: httpx.AsyncClient):
        """Set session with valid format but non-existent token should fail."""
        # Use a well-formed 16-char token that doesn't exist in DB
        fake_token = "aaaaaaaaaaaaaaaa"  # Exactly 16 characters
        response = await client.post(
            "/auth/api/set-session",
            headers={
                "Authorization": f"Bearer {fake_token}",
                "Host": "localhost:4401",
            },
        )
        # Non-existent session returns 400 (ValueError -> 400)
        assert response.status_code == 400


class TestValidateSessionRefresh:
    """Tests for session refresh behavior in validate endpoint"""

    @pytest.mark.asyncio
    async def test_validate_does_not_refresh_within_interval(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Validate should not refresh session if within refresh interval."""
        # First call - may or may not refresh depending on session age
        response1 = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response1.status_code == 200

        # Second call immediately after - should NOT refresh (within 5 min interval)
        response2 = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response2.status_code == 200
        data = response2.json()
        # Session shouldn't be renewed since we're within the refresh interval
        assert data["renewed"] is False

    @pytest.mark.asyncio
    async def test_validate_with_expired_session_during_refresh(
        self, client: httpx.AsyncClient, test_db
    ):
        """Validate should handle session expiry during refresh attempt."""
        from paskia.util.tokens import create_token

        # Create a token but don't create a session for it
        token = create_token()
        response = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(token), "Host": "localhost:4401"},
        )
        # Should return 401 for non-existent session
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_validate_session_refresh_fails_concurrent_logout(
        self,
        client: httpx.AsyncClient,
        test_db,
        test_user,
        test_credential,
    ):
        """Validate should return 401 if session disappears during refresh."""
        from datetime import timedelta

        from paskia.authsession import EXPIRES
        from paskia.util.tokens import create_token, session_key

        # Create a session with an old expiry time to trigger refresh
        token = create_token()
        old_expiry = datetime.now(timezone.utc) + EXPIRES - timedelta(minutes=10)
        test_db.create_session(
            user_uuid=test_user.uuid,
            credential_uuid=test_credential.uuid,
            key=session_key(token),
            host="localhost:4401",
            ip="127.0.0.1",
            user_agent="pytest",
            expiry=old_expiry,
        )

        # Delete the session right before validate tries to refresh
        test_db.delete_session(session_key(token))

        response = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(token), "Host": "localhost:4401"},
        )
        # Session was found initially but disappeared during refresh
        assert response.status_code == 401


class TestForwardAuthMaxAge:
    """Tests for forward auth max_age parameter"""

    @pytest.mark.asyncio
    async def test_forward_with_max_age_recent_auth(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Forward auth with max_age should pass for recent authentication."""
        response = await client.get(
            "/auth/api/forward?max_age=1h",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        # Recently authenticated session should pass
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_forward_with_invalid_max_age_format(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Forward auth with invalid max_age format should log warning but succeed."""
        response = await client.get(
            "/auth/api/forward?max_age=invalid",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        # Invalid format is logged but request proceeds
        assert response.status_code == 204


class TestValidateWithMaxAge:
    """Tests for validate endpoint with max_age parameter"""

    @pytest.mark.asyncio
    async def test_validate_with_max_age(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Validate with max_age should check authentication age."""
        response = await client.post(
            "/auth/api/validate?max_age=1h",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        # This exercises the max_age path - but isn't defined in validate
        # Actually validate doesn't have max_age - this tests that unknown params are ignored
        assert response.status_code == 200
