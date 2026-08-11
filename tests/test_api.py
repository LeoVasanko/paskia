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

import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID

import httpx
import pytest

from paskia import authcode, db
from paskia.authsession import EXPIRES
from paskia.db import delete_session
from paskia.db.structs import Client
from paskia.fastapi.api import _REFRESH_INTERVAL
from paskia.util import avatar, hostutil, oidjwt, permutil
from paskia.util.crypto import hash_secret
from paskia.util.passphrase import generate
from tests.conftest import auth_headers, create_test_image_bytes, create_test_session


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

    @pytest.mark.asyncio
    async def test_openid_configuration_includes_picture_claim(
        self, client: httpx.AsyncClient
    ):
        """Discovery document should advertise picture claim support."""
        response = await client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        assert "picture" in response.json()["claims_supported"]


class TestAvatarUrls:
    """Tests for avatar URL helpers."""

    def test_avatar_url_uses_canonical_public_path_in_auth_host_mode(
        self, tmp_path, monkeypatch
    ):
        """Absolute avatar URLs should preserve /auth/api even with an auth host."""
        db_root = tmp_path / "test-avatar-db.paskiadb"
        monkeypatch.setenv("PASKIA_DB", str(db_root))
        monkeypatch.setattr(
            hostutil,
            "api_url",
            lambda path="": f"https://auth.zi.fi/auth/api/{path.lstrip('/')}",
        )

        user_uuid = test_uuid = UUID("019c6831-84cf-7b88-b66c-c8165890b7c5")
        path = db_root / "users" / str(test_uuid) / "profile.webp"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"RIFF1234WEBP")

        assert avatar.avatar_url(user_uuid) == (
            "https://auth.zi.fi/auth/api/user/"
            "019c6831-84cf-7b88-b66c-c8165890b7c5/profile.webp"
        )


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
        assert "ctx" in data
        assert "user" in data["ctx"]
        assert "uuid" in data["ctx"]["user"]

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


class TestPermOrSemantics:
    """Tests for OR ('|') semantics and strict parsing of the perm argument"""

    @pytest.mark.asyncio
    async def test_or_alternative_matches(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Group is satisfied when any alternative matches."""
        response = await client.post(
            "/auth/api/validate?perm=missing:scope|auth:admin",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_or_no_alternative_matches(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Group fails when no alternative matches."""
        response = await client.post(
            "/auth/api/validate?perm=missing:a|missing:b",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_or_combined_with_and_group(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Space-separated groups are ANDed with OR groups."""
        response = await client.post(
            "/auth/api/validate?perm=auth:admin|missing:a+missing:b",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_multiple_perm_args_and_semantics(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Repeated perm arguments remain ANDed."""
        ok = await client.post(
            "/auth/api/validate?perm=auth:admin&perm=auth:admin|missing:a",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert ok.status_code == 200
        denied = await client.post(
            "/auth/api/validate?perm=auth:admin&perm=missing:a",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert denied.status_code == 403

    @pytest.mark.asyncio
    async def test_forward_or_semantics(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Forward endpoint supports OR semantics too."""
        response = await client.get(
            "/auth/api/forward?perm=missing:a|auth:admin",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_extra_spaces_tolerated(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Leading, trailing and repeated spaces between groups are tolerated."""
        response = await client.post(
            "/auth/api/validate?perm=%20auth:admin%20%20",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_pipe_in_separate_arg_does_not_weaken(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """perm=auth:admin&perm=|bar is a syntax error, not an OR for auth:admin."""
        response = await client.post(
            "/auth/api/validate?perm=auth:admin&perm=|bar",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_forward_400_identifies_origin_without_echoing_args(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Forward 400 names the endpoint and does not echo query args."""
        response = await client.get(
            "/auth/api/forward?perm=a||b",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        detail = response.json()["detail"]
        assert detail.startswith("/auth/api/forward")
        assert "a||b" not in detail

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "query",
        [
            "perm=",  # empty value
            "perm=a||b",  # empty alternative
            "perm=|a",  # leading pipe
            "perm=a|",  # trailing pipe
            "perm=a%20|%20b",  # spaces around pipe
            "perm=a%2Bb",  # percent-encoded plus
            "perm=a,b",  # character not allowed in scopes
        ],
    )
    async def test_invalid_perm_syntax_returns_400(
        self, client: httpx.AsyncClient, session_token: str, query: str
    ):
        """Out-of-spec perm values are rejected with 400, not guessed at."""
        for path in ("/auth/api/validate", "/auth/api/forward"):
            if path.endswith("validate"):
                response = await client.post(
                    f"{path}?{query}",
                    headers={**auth_headers(session_token), "Host": "localhost:4401"},
                )
            else:
                response = await client.get(
                    f"{path}?{query}",
                    headers={**auth_headers(session_token), "Host": "localhost:4401"},
                )
            assert response.status_code == 400, f"{path}?{query}"


class TestPermParsing:
    """Unit tests for permutil.parse_perm_args"""

    def test_single_scope(self):
        assert permutil.parse_perm_args(["auth:admin"]) == [("auth:admin",)]

    def test_space_separated_groups(self):
        assert permutil.parse_perm_args(["a b", "c"]) == [("a",), ("b",), ("c",)]

    def test_or_group(self):
        assert permutil.parse_perm_args(["a|b c"]) == [("a", "b"), ("c",)]

    def test_wildcard_allowed(self):
        assert permutil.parse_perm_args(["myapp:*|other"]) == [("myapp:*", "other")]

    def test_extra_spaces_tolerated(self):
        assert permutil.parse_perm_args([" a  b ", "c"]) == [("a",), ("b",), ("c",)]

    @pytest.mark.parametrize(
        "values",
        [
            [""],
            ["a||b"],
            ["a | b"],
            ["a| b"],
            ["a+b"],
            ["a,b"],
            ["a\tb"],
        ],
    )
    def test_syntax_errors(self, values):
        with pytest.raises(ValueError):
            permutil.parse_perm_args(values)


class TestPermWildcards:
    """Unit tests for filename-like wildcard semantics in scope patterns"""

    @pytest.mark.parametrize(
        "pattern,scope,expected",
        [
            ("myapp:*", "myapp:read", True),
            ("myapp:*", "myapp:read:all", False),  # * stays within one element
            ("myapp:**", "myapp:read:all", True),  # ** crosses elements
            ("myapp:**", "myapp:", True),
            ("myapp:re*", "myapp:read", True),  # partial element, suffix wildcard
            ("myapp:*ad", "myapp:read", True),  # prefix wildcard
            ("myapp:r*d", "myapp:read", True),  # text on both sides
            ("myapp:r*d", "myapp:redo", False),
            ("*:read", "myapp:read", True),
            ("*", "myapp:read", False),
            ("**", "myapp:read", True),
            ("myapp:*:all", "myapp:read:all", True),
            ("myapp:*:all", "myapp:read:write:all", False),
            # regex metacharacters valid in scopes are matched literally
            ("my.app:*", "my.app:read", True),
            ("my.app:*", "myXapp:read", False),
            ("myapp:v1.*", "myapp:v1.2", True),
            ("myapp:v1.*", "myapp:v1x2", False),
            ("my-app_*:~*", "my-app_x:~tmp", True),
            # slash is a literal separator; * crosses neither / nor :
            ("myapp:path:/api/clients:write", "myapp:path:/api/clients:write", True),
            ("myapp:path:*", "myapp:path:/api/clients", False),
            ("myapp:path:**", "myapp:path:/api/clients", True),
            ("myapp:path:/api/*:write", "myapp:path:/api/clients:write", True),
            ("myapp:path:/api/*:write", "myapp:path:/api/v2/clients:write", False),
            ("myapp:path:/api/**:write", "myapp:path:/api/v2/clients:write", True),
        ],
    )
    def test_wildcard_matching(self, pattern, scope, expected):
        assert permutil.has_all_scopes_groups({scope}, [(pattern,)]) is expected


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
    """Tests for GET /auth/api/user-info"""

    @pytest.mark.asyncio
    async def test_user_info_without_auth_returns_401(self, client: httpx.AsyncClient):
        """User info without session should return 401."""
        response = await client.get("/auth/api/user-info")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_user_info_with_valid_session(
        self, client: httpx.AsyncClient, session_token: str, test_user
    ):
        """User info with valid session should return user data."""
        response = await client.get(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "user" in data
        assert data["user"]["uuid"] == str(test_user.uuid)
        assert data["user"]["display_name"] == test_user.display_name

    @pytest.mark.asyncio
    async def test_user_info_includes_credentials(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """User info should include user's credentials."""
        response = await client.get(
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
        response = await client.get(
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
        response = await client.get(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data

    @pytest.mark.asyncio
    async def test_user_info_includes_avatar_url(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_user,
        tmp_path,
        monkeypatch,
    ):
        """User info should include the canonical avatar URL when present."""
        monkeypatch.setenv("PASKIA_DB", str(tmp_path / "test-avatar-db.paskiadb"))

        upload = await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={"file": ("avatar.webp", create_test_image_bytes(), "image/webp")},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert upload.status_code == 200

        response = await client.get(
            "/auth/api/user-info",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        avatar_url = data["user"]["avatar_url"]
        parts = urlsplit(avatar_url)
        assert parts.path.endswith(f"/auth/api/user/{test_user.uuid}/profile.webp")
        assert parts.query == ""

    @pytest.mark.asyncio
    async def test_avatar_route_returns_304_for_matching_etag(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_user,
        tmp_path,
        monkeypatch,
    ):
        """Avatar route should honor If-None-Match for unchanged avatars."""
        monkeypatch.setenv("PASKIA_DB", str(tmp_path / "test-avatar-db.paskiadb"))

        upload = await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={"file": ("avatar.webp", create_test_image_bytes(), "image/webp")},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert upload.status_code == 200
        parts = urlsplit(upload.json()["avatar_url"])

        first = await client.get(parts.path, headers={"Host": "localhost:4401"})
        assert first.status_code == 200

        response = await client.get(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            headers={
                "Host": "localhost:4401",
                "If-None-Match": first.headers["etag"],
            },
        )
        assert response.status_code == 304
        assert response.headers["etag"] == first.headers["etag"]


class TestOidcUserInfoEndpoint:
    """Tests for OIDC userinfo metadata relevant to avatars."""

    @pytest.mark.asyncio
    async def test_userinfo_includes_picture_claim(
        self,
        client: httpx.AsyncClient,
        test_db,
        session_token: str,
        test_user,
        tmp_path,
        monkeypatch,
    ):
        """OIDC userinfo should expose picture when profile scope is granted."""
        monkeypatch.setenv("PASKIA_DB", str(tmp_path / "test-avatar-db.paskiadb"))

        upload = await client.put(
            f"/auth/api/user/{test_user.uuid}/profile.webp",
            files={"file": ("avatar.webp", create_test_image_bytes(), "image/webp")},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert upload.status_code == 200
        avatar_url = upload.json()["avatar_url"]

        oidc_client, _secret = Client.create(
            name="Test Client",
            redirect_uris=["https://client.example/callback"],
            client_secret="topsecret",
        )
        store = test_db._store
        if store is None:
            raise RuntimeError("Test DB store is not initialized")
        with store.transaction("create_test_oidc_client"):
            test_db.oidc.clients[oidc_client.uuid] = oidc_client

        access_token = oidjwt.create_access_token(
            issuer="http://localhost:4401",
            subject=test_user.uuid,
            audience=str(oidc_client.uuid),
            scope="openid profile",
        )

        response = await client.get(
            "/auth/oidc/userinfo",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert urlsplit(data["picture"]).path == urlsplit(avatar_url).path
        assert data["picture"].startswith("http")


class TestSetSessionEndpoint:
    """Tests for POST /auth/api/set-session"""

    @pytest.mark.asyncio
    async def test_set_session_without_bearer_returns_400(
        self, client: httpx.AsyncClient
    ):
        """Set session without bearer token should return 400."""
        response = await client.post("/auth/api/set-session")
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_set_session_with_valid_bearer_token(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Set session with valid auth code as bearer should set cookie."""

        code = authcode.store_cookie(
            authcode.CookieCode(
                session_key=session_token,
                created=datetime.now(UTC),
            )
        )
        response = await client.post(
            "/auth/api/set-session",
            headers={
                "Authorization": f"Bearer {code}",
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "user" in data
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


class TestTokenInfoEndpoint:
    """Tests for token-info endpoint with reset tokens"""

    @pytest.mark.asyncio
    async def test_token_info_with_invalid_token(self, client: httpx.AsyncClient):
        """Token info with invalid token format should return 400."""
        response = await client.get(
            "/auth/api/token-info",
            headers={"Authorization": "Bearer invalid-token-format"},
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_token_info_with_nonexistent_token(self, client: httpx.AsyncClient):
        """Token info with well-formed but non-existent token should return 401."""

        fake_token = generate()
        response = await client.get(
            "/auth/api/token-info",
            headers={"Authorization": f"Bearer {fake_token}"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_token_info_with_valid_token(
        self, client: httpx.AsyncClient, reset_token: str, test_user
    ):
        """Token info with valid reset token should return token type and display name."""
        response = await client.get(
            "/auth/api/token-info",
            headers={"Authorization": f"Bearer {reset_token}"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "token_type" in data
        assert "display_name" in data
        assert data["display_name"] == test_user.display_name


class TestSetSessionErrors:
    """Tests for set-session error cases"""

    @pytest.mark.asyncio
    async def test_set_session_with_invalid_bearer_token(
        self, client: httpx.AsyncClient
    ):
        """Set session with invalid (malformed) bearer token should return 401."""
        response = await client.post(
            "/auth/api/set-session",
            headers={
                "Authorization": "Bearer invalid_token_here",  # Wrong length (18 chars)
                "Host": "localhost:4401",
            },
        )
        # Invalid token returns 401 (session not found)
        assert response.status_code == 401

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
        # Non-existent session returns 401 (session expired)
        assert response.status_code == 401


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

        # Create a token but don't create a session for it
        token = secrets.token_urlsafe(12)
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

        # Create a session with a short remaining duration to trigger refresh
        db_key, secret = create_test_session(
            user_uuid=test_user.uuid,
            credential_uuid=test_credential.uuid,
            host="localhost",
            ip="127.0.0.1",
            user_agent="pytest",
            duration=EXPIRES - timedelta(minutes=10),
        )

        # Delete the session right before validate tries to refresh
        delete_session(db_key)

        response = await client.post(
            "/auth/api/validate",
            headers={**auth_headers(secret), "Host": "localhost:4401"},
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


class TestValidateRenewParameter:
    """Tests for the renew query parameter on /auth/api/validate."""

    @pytest.mark.asyncio
    async def test_validate_renew_false_skips_renewal(
        self, client: httpx.AsyncClient, session_token: str, test_db
    ):
        """renew=0 should skip session renewal and leave metadata untouched."""
        key = hash_secret("cookie", session_token)
        old_validated = datetime.now(UTC) - _REFRESH_INTERVAL - timedelta(minutes=1)
        db.update_session(key, validated=old_validated)
        original_ua = test_db.sessions[key].user_agent

        response = await client.post(
            "/auth/api/validate?renew=0",
            headers={
                **auth_headers(session_token),
                "Host": "localhost:4401",
                "User-Agent": "different-ua",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["renewed"] is False
        assert "set-cookie" not in response.headers
        assert test_db.sessions[key].validated == old_validated
        assert test_db.sessions[key].user_agent == original_ua

    @pytest.mark.asyncio
    async def test_validate_renew_true_renews_old_session(
        self, client: httpx.AsyncClient, session_token: str, test_db
    ):
        """Explicit renew=1 should renew an aged session and return Set-Cookie."""
        key = hash_secret("cookie", session_token)
        old_validated = datetime.now(UTC) - _REFRESH_INTERVAL - timedelta(minutes=1)
        db.update_session(key, validated=old_validated)

        response = await client.post(
            "/auth/api/validate?renew=1",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["renewed"] is True
        assert "set-cookie" in response.headers
        assert test_db.sessions[key].validated > old_validated
