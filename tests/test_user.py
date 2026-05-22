"""
Tests for the user API endpoints (/auth/api/user/).

These tests cover user self-service operations:
- Display name update
- Avatar upload/delete
- Logout all sessions
- Session management (delete specific session)
- Credential management (delete credential)
- Device addition link creation
"""

from urllib.parse import urlsplit

import httpx
import pytest

from paskia.db.paths import db_file_path, users_root_path
from tests.conftest import auth_headers, create_test_image_bytes


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


class TestUserAvatar:
    """Tests for PUT/DELETE /auth/api/user/{user_uuid}/profile.webp"""

    @pytest.mark.asyncio
    async def test_upload_avatar_requires_auth(self, client: httpx.AsyncClient):
        """Uploading avatar without auth should return 401."""
        response = await client.put(
            "/auth/api/user/00000000-0000-0000-0000-000000000000/profile.webp",
            files={"file": ("avatar.webp", create_test_image_bytes(), "image/webp")},
        )
        assert response.status_code in (401, 404)

    @pytest.mark.asyncio
    async def test_upload_avatar_success(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_user,
        tmp_path,
        monkeypatch,
    ):
        """Uploading a WebP avatar should store and expose the canonical URL."""
        monkeypatch.setenv("PASKIA_DB", str(tmp_path / "test-avatar-db.paskiadb"))

        upload_bytes = create_test_image_bytes()

        response = await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={"file": ("avatar.webp", upload_bytes, "image/webp")},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        avatar_url = data["avatar_url"]
        parts = urlsplit(avatar_url)
        assert parts.query == ""

        avatar_response = await client.get(
            parts.path,
            headers={"Host": "localhost:4401"},
        )
        assert avatar_response.status_code == 200
        assert avatar_response.headers["cache-control"] == "public, max-age=300"
        assert avatar_response.headers["content-type"] == "image/webp"
        assert "etag" in avatar_response.headers
        assert avatar_response.content == upload_bytes

        not_modified = await client.get(
            parts.path,
            headers={
                "Host": "localhost:4401",
                "If-None-Match": avatar_response.headers["etag"],
            },
        )
        assert not_modified.status_code == 304
        assert not_modified.headers["etag"] == avatar_response.headers["etag"]

    @pytest.mark.asyncio
    async def test_upload_avatar_rejects_non_webp(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_user,
        tmp_path,
        monkeypatch,
    ):
        """Avatar uploads must already be browser-prepared WebP."""
        monkeypatch.setenv("PASKIA_DB", str(tmp_path / "test-avatar-db.paskiadb"))

        response = await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={
                "file": (
                    "avatar.png",
                    create_test_image_bytes(image_format="PNG"),
                    "image/png",
                )
            },
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )

        assert response.status_code == 400
        assert response.json()["detail"] == "Avatar upload must be WebP"

    @pytest.mark.asyncio
    async def test_delete_avatar_success(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_user,
        tmp_path,
        monkeypatch,
    ):
        """Deleting avatar should clear the user avatar URL."""
        monkeypatch.setenv("PASKIA_DB", str(tmp_path / "test-avatar-db.paskiadb"))

        await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={"file": ("avatar.webp", create_test_image_bytes(), "image/webp")},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )

        response = await client.delete(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

        info = await client.get(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert info.status_code == 200
        assert info.json()["user"].get("avatar_url") is None

    @pytest.mark.asyncio
    async def test_regular_user_cannot_upload_another_users_avatar(
        self,
        client: httpx.AsyncClient,
        regular_session_token: str,
        session_token: str,
        test_user,
    ):
        """A non-admin user should not be able to upload another user's avatar."""
        response = await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={"file": ("avatar.webp", create_test_image_bytes(), "image/webp")},
            headers={**auth_headers(regular_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403


def test_paskia_db_legacy_file_is_migrated_to_root_dir(tmp_path, monkeypatch):
    legacy_path = tmp_path / "legacy.paskiadb"
    legacy_bytes = b'{"v":0}\n'
    legacy_path.write_bytes(legacy_bytes)

    monkeypatch.setenv("PASKIA_DB", str(legacy_path))

    db_path = db_file_path(create_root=True)

    assert legacy_path.is_dir()
    assert db_path == legacy_path / "main.db"
    assert db_path.read_bytes() == legacy_bytes


def test_paskia_db_root_uses_users_directory(tmp_path, monkeypatch):
    root_path = tmp_path / "instance-root"
    monkeypatch.setenv("PASKIA_DB", str(root_path))

    users_path = users_root_path(create_root=True)

    assert users_path == root_path / "users"
    assert users_path.parent == root_path


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
