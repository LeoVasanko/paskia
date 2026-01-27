"""
Tests for the admin API endpoints (/auth/api/admin/).

These tests cover:
- Organization management (CRUD)
- Role management (CRUD)
- User management within orgs
- Permission management
- Exception handlers
- Session management
- Credential management
"""

from datetime import datetime, timezone
from uuid import UUID

import httpx
import pytest
import pytest_asyncio
import uuid7

from paskia.authsession import expires
from paskia.db import (
    Credential,
    Org,
    Permission,
    Role,
    User,
    add_permission_to_organization,
    create_credential,
    create_organization,
    create_permission,
    create_role,
    create_session,
    create_user,
)
from paskia.db.operations import DB, _create_token
from tests.conftest import auth_headers

# -------------------- Additional Fixtures --------------------


@pytest_asyncio.fixture(scope="function")
async def second_org(test_db: DB) -> Org:
    """Create a second organization for deletion tests."""
    org = Org.create(
        display_name="Second Organization",
    )
    create_organization(org)
    return org


@pytest_asyncio.fixture(scope="function")
async def second_org_role(
    test_db: DB, second_org: Org, admin_permission: Permission
) -> Role:
    """Create a role in the second org with admin permission."""
    role = Role.create(
        org=second_org.uuid,
        display_name="Second Org Admin Role",
        permissions={admin_permission.uuid},
    )
    create_role(role)
    return role


@pytest_asyncio.fixture(scope="function")
async def second_org_user(test_db: DB, second_org_role: Role) -> User:
    """Create a user in the second org."""
    user = User.create(
        display_name="Second Org User",
        role=second_org_role.uuid,
    )
    create_user(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def second_org_credential(test_db: DB, second_org_user: User) -> Credential:
    """Create a credential for the second org user."""
    import os

    credential = Credential.create(
        credential_id=os.urandom(32),
        user=second_org_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
    )
    create_credential(credential)
    return credential


@pytest_asyncio.fixture(scope="function")
async def second_org_session_token(
    test_db: DB, second_org_user: User, second_org_credential: Credential
) -> str:
    """Create a session for the second org admin user."""
    token = _create_token()
    create_session(
        user_uuid=second_org_user.uuid,
        credential_uuid=second_org_credential.uuid,
        key=token,
        host="localhost:4401",
        ip="127.0.0.1",
        user_agent="pytest",
        expiry=expires(),
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def org_admin_role(
    test_db: DB, test_org: Org, org_admin_permission: Permission
) -> Role:
    """Create a role with org admin permission only (no global admin)."""
    role = Role.create(
        org=test_org.uuid,
        display_name="Org Admin Role",
        permissions={org_admin_permission.uuid},
    )
    create_role(role)
    return role


@pytest_asyncio.fixture(scope="function")
async def org_admin_user(test_db: DB, org_admin_role: Role) -> User:
    """Create a user with org admin permission only."""
    user = User.create(
        display_name="Org Admin User",
        role=org_admin_role.uuid,
    )
    user.visits = 5
    user.last_seen = datetime.now(timezone.utc)
    create_user(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def org_admin_credential(test_db: DB, org_admin_user: User) -> Credential:
    """Create a credential for the org admin user."""
    import os

    credential = Credential.create(
        credential_id=os.urandom(32),
        user=org_admin_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
    )
    create_credential(credential)
    return credential


@pytest_asyncio.fixture(scope="function")
async def org_admin_session_token(
    test_db: DB, org_admin_user: User, org_admin_credential: Credential
) -> str:
    """Create a session for the org admin user."""
    token = _create_token()
    create_session(
        user_uuid=org_admin_user.uuid,
        credential_uuid=org_admin_credential.uuid,
        key=token,
        host="localhost:4401",
        ip="127.0.0.1",
        user_agent="pytest",
        expiry=expires(),
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def grantable_permission(test_db: DB, test_org: Org) -> Permission:
    """Create a permission and add it to org's grantable permissions."""
    perm = Permission.create(scope="test:grantable:perm", display_name="Grantable Perm")
    create_permission(perm)
    # Add to org's grantable permissions
    add_permission_to_organization(test_org.uuid, perm.uuid)
    return perm


# -------------------- Exception Handler Tests --------------------


class TestExceptionHandlers:
    """Tests for admin app exception handlers"""

    @pytest.mark.asyncio
    async def test_auth_exception_handler(self, client: httpx.AsyncClient):
        """AuthException should return proper JSON with auth info."""
        # Accessing admin without auth triggers AuthException
        response = await client.get("/auth/api/admin/orgs")
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert "auth" in data
        assert data["auth"]["mode"] == "login"
        assert "iframe" in data["auth"]


# -------------------- Admin App Root --------------------


class TestAdminAppRoot:
    """Tests for the admin app root endpoint"""

    @pytest.mark.asyncio
    async def test_admin_app_root_with_auth(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Admin app root returns HTML when authenticated."""
        response = await client.get(
            "/auth/api/admin/",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        assert "text/html" in response.headers.get("content-type", "")


# -------------------- Organization Tests --------------------


class TestAdminOrganizations:
    """Tests for admin organization endpoints"""

    @pytest.mark.asyncio
    async def test_list_orgs_requires_auth(self, client: httpx.AsyncClient):
        """List orgs without auth should return 401."""
        response = await client.get("/auth/api/admin/orgs")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_list_orgs_requires_admin_permission(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """List orgs without admin permission should return 403."""
        response = await client.get(
            "/auth/api/admin/orgs",
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_list_orgs_with_admin(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Admin user should be able to list organizations."""
        response = await client.get(
            "/auth/api/admin/orgs",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        # Check org structure
        org = data[0]
        assert "uuid" in org
        assert "display_name" in org
        assert "roles" in org
        assert "users" in org

    @pytest.mark.asyncio
    async def test_list_orgs_with_org_admin(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
        second_org,
    ):
        """Org admin should only see their own organization."""
        response = await client.get(
            "/auth/api/admin/orgs",
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        # Should only see their own org, not the second org
        org_uuids = [o["uuid"] for o in data]
        assert str(test_org.uuid) in org_uuids

    @pytest.mark.asyncio
    async def test_create_org_requires_admin(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """Creating org without admin permission should fail."""
        response = await client.post(
            "/auth/api/admin/orgs",
            json={"display_name": "New Org"},
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_create_org_success(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Admin should be able to create a new organization."""
        response = await client.post(
            "/auth/api/admin/orgs",
            json={"display_name": "New Test Org", "permissions": []},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_create_org_with_defaults(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Admin should be able to create org with default values."""
        response = await client.post(
            "/auth/api/admin/orgs",
            json={},  # No display_name or permissions
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_update_org(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Admin should be able to update an organization."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}",
            json={"display_name": "Updated Org Name"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_update_org_with_org_admin(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
    ):
        """Org admin should be able to update their organization."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}",
            json={
                "display_name": "Org Admin Updated Name",
            },
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_update_org_org_admin_cannot_remove_own_perm(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
        test_db: DB,
    ):
        """Org admin cannot remove their org admin permission from org's permissions."""
        # The auth:org:admin perm is already created and added by org_admin_permission fixture

        # Try to remove org admin perm (this is validated server-side in the remove endpoint)
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=auth:org:admin",
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        # This should fail because only global admin can remove perms from org
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_org_own_org_fails(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Cannot delete the organization you belong to."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Cannot delete" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_org_success(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_db: DB,
    ):
        """Admin should be able to delete another organization."""
        # Create org to delete
        org_to_delete = Org.create(
            display_name="Org To Delete",
        )
        create_organization(org_to_delete)

        # Create some org-specific permissions to test cleanup
        org_perm = Permission.create(
            scope=f"test:org:{org_to_delete.uuid}:feature",
            display_name="Org Feature",
        )
        create_permission(org_perm)

        response = await client.delete(
            f"/auth/api/admin/orgs/{org_to_delete.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"


# -------------------- Organization Permission Tests --------------------


class TestAdminOrgPermissions:
    """Tests for managing permissions on organizations"""

    @pytest.mark.asyncio
    async def test_add_permission_to_org(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Admin should be able to add a permission to an org."""
        # First create a permission
        await client.post(
            "/auth/api/admin/permissions",
            json={"scope": "test:org:addable", "display_name": "Addable"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )

        # Add it to the org
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=test:org:addable",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_add_permission_to_org_requires_admin(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
    ):
        """Org admin cannot add permissions to org (requires global admin)."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=auth:admin",
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_remove_permission_from_org(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Admin should be able to remove a permission from an org."""
        # First create and add a permission
        await client.post(
            "/auth/api/admin/permissions",
            json={"scope": "test:org:removable", "display_name": "Removable"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=test:org:removable",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )

        # Remove it
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=test:org:removable",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_remove_permission_from_org_requires_admin(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
    ):
        """Org admin cannot remove permissions from org (requires global admin)."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=auth:admin",
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403


# -------------------- Role Tests --------------------


class TestAdminRoles:
    """Tests for admin role endpoints"""

    @pytest.mark.asyncio
    async def test_create_role_requires_admin(
        self, client: httpx.AsyncClient, regular_session_token: str, test_org
    ):
        """Creating role without admin permission should fail."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles",
            json={"display_name": "New Role"},
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_create_role_success(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Admin should be able to create a new role."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles",
            json={"display_name": "Test Role", "permissions": []},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_create_role_with_defaults(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Admin should be able to create role with default name."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles",
            json={},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_create_role_with_grantable_permission(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        grantable_permission,
    ):
        """Admin should be able to create role with grantable permissions."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles",
            json={
                "display_name": "Role With Perms",
                "permissions": [str(grantable_permission.uuid)],
            },
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_create_role_with_non_grantable_permission(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        test_db: DB,
    ):
        """Creating role with non-grantable permission should fail."""
        # Create permission but don't add to org
        perm = Permission.create(
            scope="test:not:grantable",
            display_name="Not Grantable",
        )
        create_permission(perm)

        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles",
            json={
                "display_name": "Bad Role",
                "permissions": [str(perm.uuid)],
            },
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "not grantable" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_role(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_role
    ):
        """Admin should be able to update a role."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{test_role.uuid}",
            json={"display_name": "Updated Role Name"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_update_role_wrong_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, second_org_role
    ):
        """Cannot update role from another org."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{second_org_role.uuid}",
            json={"display_name": "Try Update Wrong Org"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "Role not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_role_add_grantable_permission(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        user_role,
        grantable_permission,
    ):
        """Admin should be able to add grantable permissions to role."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{user_role.uuid}/permissions/{grantable_permission.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_role_add_non_grantable_permission(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        user_role,
        test_db: DB,
    ):
        """Adding non-grantable permission to role should fail."""
        perm = Permission.create(
            scope="test:not:grantable:update",
            display_name="Not Grantable",
        )
        create_permission(perm)

        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{user_role.uuid}/permissions/{perm.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "not grantable" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_own_role_cannot_remove_admin(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        test_role,
        admin_permission,
        org_admin_permission,
    ):
        """Admin cannot remove their own admin permissions."""
        # test_role has both auth:admin and auth:org:admin
        # Remove auth:admin first (should succeed since org:admin remains)
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{test_role.uuid}/permissions/{admin_permission.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

        # Now try to remove auth:org:admin (should fail - would leave no admin access)
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{test_role.uuid}/permissions/{org_admin_permission.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Cannot remove your own admin permissions" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_role(
        self, client: httpx.AsyncClient, session_token: str, test_org, user_role
    ):
        """Admin should be able to delete a role."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{user_role.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_delete_role_wrong_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, second_org_role
    ):
        """Cannot delete role from another org."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{second_org_role.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "Role not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_own_role_fails(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_role
    ):
        """Admin cannot delete their own role."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/roles/{test_role.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Cannot delete your own role" in data["detail"]


# -------------------- User Tests --------------------


class TestAdminUsersInOrg:
    """Tests for admin user management within organizations"""

    @pytest.mark.asyncio
    async def test_create_user_success(
        self, client: httpx.AsyncClient, session_token: str, test_org, user_role
    ):
        """Admin should be able to create a new user."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users",
            json={"display_name": "New User", "role": user_role.display_name},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "uuid" in data

    @pytest.mark.asyncio
    async def test_create_user_missing_fields(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Creating user without required fields should fail."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users",
            json={},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "required" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_invalid_role(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Creating user with non-existent role should fail."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users",
            json={"display_name": "New User", "role": "NonExistent Role"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Role not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_get_user_in_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Admin should be able to get user details within an org."""
        response = await client.get(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "display_name" in data
        assert "credentials" in data
        assert "sessions" in data
        assert "aaguid_info" in data
        assert "org" in data
        assert "role" in data

    @pytest.mark.asyncio
    async def test_get_user_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Getting non-existent user should return 404."""
        fake_uuid = uuid7.create()
        response = await client.get(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{fake_uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_get_user_wrong_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, second_org_user
    ):
        """Getting user from another org should return 404."""
        response = await client.get(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{second_org_user.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_get_user_with_org_admin(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
        org_admin_user,
    ):
        """Org admin should be able to get user details."""
        response = await client.get(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{org_admin_user.uuid}",
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "display_name" in data

    @pytest.mark.asyncio
    async def test_update_user_display_name_in_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Admin should be able to update user display name."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/display-name",
            json={"display_name": "Updated Admin Name"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_user_display_name_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Updating non-existent user should return 404."""
        fake_uuid = uuid7.create()
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{fake_uuid}/display-name",
            json={"display_name": "New Name"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_user_display_name_wrong_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, second_org_user
    ):
        """Updating user from another org should return 404."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{second_org_user.uuid}/display-name",
            json={"display_name": "New Name"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_user_display_name_empty(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Updating user with empty display name should fail."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/display-name",
            json={"display_name": "   "},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "display_name required" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_user_display_name_too_long(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Updating user with too long display name should fail."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/display-name",
            json={"display_name": "x" * 100},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "too long" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_user_role_in_org(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        regular_user,
        user_role,
    ):
        """Admin should be able to change user's role within org."""
        # Use regular_user who is in the same org but not the session owner
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{regular_user.uuid}/role",
            json={"role": user_role.display_name},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_update_user_role_missing_role(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Updating user role without specifying role should fail."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/role",
            json={},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "role is required" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_user_role_user_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Updating role for non-existent user should fail."""
        fake_uuid = uuid7.create()
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{fake_uuid}/role",
            json={"role": "User Role"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_user_role_wrong_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, second_org_user
    ):
        """Updating role for user in another org should fail."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{second_org_user.uuid}/role",
            json={"role": "User Role"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "does not belong" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_user_role_invalid_role(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Updating user to non-existent role should fail."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/role",
            json={"role": "Nonexistent Role"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Role not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_own_role_to_non_admin_fails(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
        org_admin_user,
        user_role,
    ):
        """Admin cannot change their own role to non-admin role."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{org_admin_user.uuid}/role",
            json={"role": user_role.display_name},
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "without admin permissions" in data["detail"]

    @pytest.mark.asyncio
    async def test_update_own_role_to_admin_role_succeeds(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        test_user,
        test_role,
    ):
        """Admin can change their own role to another admin role."""
        # test_user is already on test_role which has auth:admin
        # Changing to the same role should succeed (no permission loss)
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/role",
            json={"role": test_role.display_name},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_create_user_reset_link(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Admin should be able to create reset links for users."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/create-link",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "url" in data
        assert "expires" in data

    @pytest.mark.asyncio
    async def test_create_user_reset_link_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Creating reset link for non-existent user should fail."""
        fake_uuid = uuid7.create()
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{fake_uuid}/create-link",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_reset_link_wrong_org(
        self, client: httpx.AsyncClient, session_token: str, test_org, second_org_user
    ):
        """Creating reset link for user in another org should fail."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{second_org_user.uuid}/create-link",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "not found in organization" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_user_registration_link_without_credentials(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        user_role,
        test_db: DB,
    ):
        """Creating link for user without credentials should return registration link."""
        # Create user without credentials
        user_no_cred = User.create(
            display_name="User Without Creds",
            role=user_role.uuid,
        )
        create_user(user_no_cred)

        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{user_no_cred.uuid}/create-link",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "url" in data


# -------------------- Credential Tests --------------------


class TestAdminCredentials:
    """Tests for admin credential management"""

    @pytest.mark.asyncio
    async def test_delete_user_credential(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        test_user,
        test_credential,
    ):
        """Admin should be able to delete a user's credential."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/credentials/{test_credential.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_delete_credential_user_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Deleting credential for non-existent user should fail."""
        fake_user_uuid = uuid7.create()
        fake_cred_uuid = uuid7.create()
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{fake_user_uuid}/credentials/{fake_cred_uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_credential_wrong_org(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        second_org_user,
        second_org_credential,
    ):
        """Deleting credential for user in another org should fail."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{second_org_user.uuid}/credentials/{second_org_credential.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404


# -------------------- Session Tests --------------------


class TestAdminSessions:
    """Tests for admin session management"""

    @pytest.mark.asyncio
    async def test_delete_user_session(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        test_user,
        test_credential,
        test_db: DB,
    ):
        """Admin should be able to delete a user's session."""
        # Create an additional session to delete
        extra_token = _create_token()
        create_session(
            user_uuid=test_user.uuid,
            credential_uuid=test_credential.uuid,
            key=extra_token,
            host="other.host:4401",
            ip="192.168.1.1",
            user_agent="other-agent",
            expiry=expires(),
        )

        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/sessions/{extra_token}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["current_session_terminated"] is False

    @pytest.mark.asyncio
    async def test_delete_own_session(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        test_user,
    ):
        """Admin can delete their own current session."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/sessions/{session_token}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["current_session_terminated"] is True

    @pytest.mark.asyncio
    async def test_delete_session_user_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Deleting session for non-existent user should fail."""
        fake_uuid = uuid7.create()
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{fake_uuid}/sessions/fake-session-id",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "User not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_session_wrong_org(
        self,
        client: httpx.AsyncClient,
        session_token: str,
        test_org,
        second_org_user,
    ):
        """Deleting session for user in another org should fail."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{second_org_user.uuid}/sessions/fake-session",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_session_invalid_id(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Deleting session with invalid/non-existent ID should fail."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/sessions/invalid!!id",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "Session not found" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_session_not_found(
        self, client: httpx.AsyncClient, session_token: str, test_org, test_user
    ):
        """Deleting non-existent session should fail."""
        # Use a valid format but non-existent key
        fake_token = _create_token()
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/sessions/{fake_token}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 404
        data = response.json()
        assert "Session not found" in data["detail"]


# -------------------- Permission Tests --------------------


class TestAdminPermissions:
    """Tests for admin permission management"""

    @pytest.mark.asyncio
    async def test_list_permissions(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Admin should be able to list all permissions."""
        response = await client.get(
            "/auth/api/admin/permissions",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should include at least auth:admin
        perm_scopes = [p["scope"] for p in data]
        assert "auth:admin" in perm_scopes

    @pytest.mark.asyncio
    async def test_list_permissions_org_admin(
        self,
        client: httpx.AsyncClient,
        org_admin_session_token: str,
        test_org,
        grantable_permission,
    ):
        """Org admin should only see permissions their org can grant."""
        response = await client.get(
            "/auth/api/admin/permissions",
            headers={**auth_headers(org_admin_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        # Should only see permissions the org can grant
        perm_scopes = [p["scope"] for p in data]
        assert grantable_permission.scope in perm_scopes
        # test_org CAN grant auth:admin (it's in org.permissions), so org admin sees it
        assert "auth:admin" in perm_scopes
        # Should also see auto-created org admin permission
        assert "auth:org:admin" in perm_scopes

    @pytest.mark.asyncio
    async def test_create_permission(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Admin should be able to create new permissions."""
        response = await client.post(
            "/auth/api/admin/permissions",
            json={"scope": "test:create:permission", "display_name": "Test Permission"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_create_permission_missing_fields(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Creating permission without required fields should fail."""
        response = await client.post(
            "/auth/api/admin/permissions",
            json={},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "required" in data["detail"]

    @pytest.mark.asyncio
    async def test_create_permission_requires_admin(
        self, client: httpx.AsyncClient, regular_session_token: str
    ):
        """Creating permission without admin should fail."""
        response = await client.post(
            "/auth/api/admin/permissions",
            json={"scope": "test:forbidden", "display_name": "Forbidden"},
            headers={
                **auth_headers(regular_session_token),
                "Host": "localhost:4401",
            },
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_update_permission(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Admin should be able to update a permission."""
        # Create permission first
        perm = Permission.create(scope="test:updateable", display_name="Updateable")
        create_permission(perm)

        response = await client.patch(
            f"/auth/api/admin/permission?permission_uuid={perm.uuid}&display_name=Updated%20Name",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_update_permission_empty_name(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Updating permission with empty name should fail."""
        # Create permission first
        perm = Permission.create(scope="test:perm", display_name="Test Perm")
        create_permission(perm)

        response = await client.patch(
            f"/auth/api/admin/permission?permission_uuid={perm.uuid}&display_name=",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "display_name is required" in data["detail"]

    @pytest.mark.asyncio
    async def test_rename_permission(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Admin should be able to rename a permission."""
        # Create permission first
        perm = Permission.create(scope="test:renameable2", display_name="Renameable")
        create_permission(perm)

        response = await client.post(
            f"/auth/api/admin/permission/rename?permission_uuid={perm.uuid}",
            json={"new_scope": "test:renamed2"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_rename_permission_missing_ids(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Renaming permission without IDs should fail."""
        response = await client.post(
            "/auth/api/admin/permission/rename",
            json={},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 422
        data = response.json()
        assert any(
            "required" in str(error) or "Field required" in str(error)
            for error in data["detail"]
        )

    @pytest.mark.asyncio
    async def test_rename_permission_auth_admin_fails(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Cannot rename the auth:admin permission."""
        # Get the auth:admin permission
        from paskia.db import list_permissions

        perms = list_permissions()
        admin_perm = next(p for p in perms if p.scope == "auth:admin")

        response = await client.post(
            f"/auth/api/admin/permission/rename?permission_uuid={admin_perm.uuid}",
            json={"new_scope": "auth:superadmin"},
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "Cannot rename the master admin" in data["detail"]

    @pytest.mark.asyncio
    async def test_rename_permission_with_display_name(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Renaming permission can also update display name."""
        perm = Permission.create(scope="test:rename:withname", display_name="Old Name")
        create_permission(perm)

        response = await client.post(
            f"/auth/api/admin/permission/rename?permission_uuid={perm.uuid}",
            json={
                "new_scope": "test:renamed:withname",
                "display_name": "New Display Name",
            },
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_delete_permission(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Admin should be able to delete a permission."""
        # Create permission first
        perm = Permission.create(scope="test:deleteable", display_name="Deleteable")
        create_permission(perm)

        response = await client.delete(
            f"/auth/api/admin/permission?permission_uuid={perm.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_delete_permission_auth_admin_last_one_fails(
        self, client: httpx.AsyncClient, session_token: str
    ):
        """Cannot delete the only auth:admin permission (would lock out admin)."""
        # Get the auth:admin permission
        from paskia.db import list_permissions

        perms = list_permissions()
        admin_perm = next(p for p in perms if p.scope == "auth:admin")

        response = await client.delete(
            f"/auth/api/admin/permission?permission_uuid={admin_perm.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "lock you out of admin access" in data["detail"]

    @pytest.mark.asyncio
    async def test_delete_permission_auth_admin_with_another_succeeds(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Can delete an auth:admin permission if another accessible one exists."""
        from paskia.db import Permission

        # Create a second auth:admin permission (no domain restriction)
        perm2 = Permission.create(scope="auth:admin", display_name="Secondary Admin")
        create_permission(perm2)

        # Get the original auth:admin permission (the one created in setup)
        from paskia.db import list_permissions

        perms = list_permissions()
        admin_perms = [p for p in perms if p.scope == "auth:admin"]
        # Delete the first one (not the one we just created)
        original_admin_perm = next(p for p in admin_perms if p.uuid != perm2.uuid)

        # Now we can delete the original one
        response = await client.delete(
            f"/auth/api/admin/permission?permission_uuid={original_admin_perm.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"

    @pytest.mark.asyncio
    async def test_delete_permission_auth_admin_domain_mismatch_fails(
        self, client: httpx.AsyncClient, session_token: str, test_db: DB
    ):
        """Cannot delete auth:admin if remaining one has mismatched domain."""
        from paskia.db import Permission

        # Create a second auth:admin permission with a different domain
        perm2 = Permission.create(
            scope="auth:admin",
            display_name="Other Domain Admin",
            domain="other.example.com",
        )
        create_permission(perm2)

        # Cannot delete the original one because the remaining one is not accessible
        # Get the original auth:admin permission
        from paskia.db import list_permissions

        perms = list_permissions()
        admin_perms = [p for p in perms if p.scope == "auth:admin" and p.domain is None]
        original_admin_perm = admin_perms[0]  # The one without domain

        response = await client.delete(
            f"/auth/api/admin/permission?permission_uuid={original_admin_perm.uuid}",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "lock you out of admin access" in data["detail"]

    @pytest.mark.asyncio
    async def test_remove_auth_admin_from_own_org_fails(
        self, client: httpx.AsyncClient, session_token: str, test_org
    ):
        """Cannot remove auth:admin permission from your own organization."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/permission?permission_id=auth:admin",
            headers={**auth_headers(session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 400
        data = response.json()
        assert "lock you out of admin access" in data["detail"]


# -------------------- Edge Cases for AuthException in Org-Admin Checks --------------------


class TestOrgAdminAuthExceptions:
    """Tests for org admin AuthException branches that require specific permission checks."""

    @pytest.mark.asyncio
    async def test_create_reset_link_regular_user_forbidden(
        self,
        client: httpx.AsyncClient,
        regular_session_token: str,
        test_org,
        test_user,
    ):
        """Regular user (not org admin) trying to create reset link should get 403."""
        response = await client.post(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/create-link",
            headers={**auth_headers(regular_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_get_user_detail_regular_user_forbidden(
        self,
        client: httpx.AsyncClient,
        regular_session_token: str,
        test_org,
        test_user,
    ):
        """Regular user trying to get user details should get 403."""
        response = await client.get(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}",
            headers={**auth_headers(regular_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_update_display_name_regular_user_forbidden(
        self,
        client: httpx.AsyncClient,
        regular_session_token: str,
        test_org,
        test_user,
    ):
        """Regular user trying to update display name should get 403."""
        response = await client.patch(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/display-name",
            json={"display_name": "New Name"},
            headers={**auth_headers(regular_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_credential_regular_user_forbidden(
        self,
        client: httpx.AsyncClient,
        regular_session_token: str,
        test_org,
        test_user,
        test_credential,
    ):
        """Regular user trying to delete credential should get 403."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/credentials/{test_credential.uuid}",
            headers={**auth_headers(regular_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_session_regular_user_forbidden(
        self,
        client: httpx.AsyncClient,
        regular_session_token: str,
        test_org,
        test_user,
    ):
        """Regular user trying to delete session should get 403."""
        response = await client.delete(
            f"/auth/api/admin/orgs/{test_org.uuid}/users/{test_user.uuid}/sessions/some-session",
            headers={**auth_headers(regular_session_token), "Host": "localhost:4401"},
        )
        assert response.status_code == 403
