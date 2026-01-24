"""
Tests for the user API endpoints (/auth/api/user/).

These tests cover user self-service operations:
- Display name update
- Logout all sessions
- Session management (delete specific session)
- Credential management (delete credential)
- Device addition link creation
"""

import httpx
import pytest

from tests.conftest import auth_headers


class TestUserDisplayName:
    """Tests for PATCH /auth/api/user/display-name"""

    @pytest.mark.asyncio
    async def test_update_display_name_requires_auth(self, client: httpx.AsyncClient):
        """Update display name without auth should return 401."""
        response = await client.patch(
            "/auth/api/user/display-name",
            json={"display_name": "New Name"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_update_display_name_success(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User should be able to update their display name."""
        response = await client.patch(
            "/auth/api/user/display-name",
            json={"display_name": "Updated Name"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_update_display_name_empty_fails(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Empty display name should fail."""
        response = await client.patch(
            "/auth/api/user/display-name",
            json={"display_name": ""},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_update_display_name_too_long_fails(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Display name over 64 chars should fail."""
        long_name = "x" * 100
        response = await client.patch(
            "/auth/api/user/display-name",
            json={"display_name": long_name},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400


class TestUserLogoutAll:
    """Tests for POST /auth/api/user/logout-all"""

    @pytest.mark.asyncio
    async def test_logout_all_requires_auth(self, client: httpx.AsyncClient):
        """Logout all without auth should return already logged out."""
        response = await client.post("/auth/api/user/logout-all")
        assert response.status_code == 200
        data = response.json()
        assert "Already logged out" in data["message"]

    @pytest.mark.asyncio
    async def test_logout_all_success(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User should be able to logout from all sessions."""
        response = await client.post(
            "/auth/api/user/logout-all",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "Logged out" in data["message"]

        # Verify session is invalidated
        response2 = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response2.status_code == 401


class TestUserSessionManagement:
    """Tests for DELETE /auth/api/user/session/{session_id}"""

    @pytest.mark.asyncio
    async def test_delete_session_requires_auth(self, client: httpx.AsyncClient):
        """Delete session without auth should return 401."""
        response = await client.delete("/auth/api/user/session/fake-session-id")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_invalid_session_fails(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Deleting invalid session ID should fail."""
        response = await client.delete(
            "/auth/api/user/session/invalid-session-id",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404  # Not found (no format validation)

    @pytest.mark.asyncio
    async def test_delete_nonexistent_session_returns_404(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Deleting a properly-formatted but nonexistent session returns 404."""
        # Use a valid format but non-existent session key
        fake_session = "c2Vzc0FBQUFBQUFBQUFBQUFBQUE"  # base64 of "sessAAAAAAAAAAAAAAAA"
        response = await client.delete(
            f"/auth/api/user/session/{fake_session}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404


class TestUserCredentialManagement:
    """Tests for DELETE /auth/api/user/credential/{uuid}"""

    @pytest.mark.asyncio
    async def test_delete_credential_requires_auth(self, client: httpx.AsyncClient):
        """Delete credential without auth should return 401."""
        response = await client.delete(
            "/auth/api/user/credential/00000000-0000-0000-0000-000000000000"
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_delete_credential_success(
        self, client: httpx.AsyncClient, session_token: str, test_credential
    ):
        """User can delete their credential."""
        response = await client.delete(
            f"/auth/api/user/credential/{test_credential.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        # Note: API allows deleting even the only credential
        assert response.status_code == 200
        data = response.json()
        assert "deleted" in data["message"].lower()


class TestUserCreateLink:
    """Tests for POST /auth/api/user/create-link"""

    @pytest.mark.asyncio
    async def test_create_link_requires_auth(self, client: httpx.AsyncClient):
        """Create link without auth should return 401."""
        response = await client.post("/auth/api/user/create-link")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_link_success(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User should be able to create a device addition link."""
        response = await client.post(
            "/auth/api/user/create-link",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "url" in data
        assert "expires" in data
        assert "message" in data
