"""
Pytest configuration and fixtures for Paskia API tests.

FastAPI provides excellent testing support through httpx.ASGITransport,
which allows us to make async requests directly to the ASGI app without
running a server.

Since we can't emulate WebAuthn passkeys, we create sessions directly
in the database to test authenticated endpoints.
"""

import asyncio
import os
import tempfile
from collections.abc import AsyncGenerator
from uuid import UUID

import httpx
import pytest
import pytest_asyncio

from paskia import globals as paskia_globals
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
    create_reset_token,
    create_role,
    create_session,
    create_user,
)
from paskia.db.operations import DB, _create_token
from paskia.fastapi.session import AUTH_COOKIE_NAME
from paskia.sansio import Passkey


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def test_db() -> AsyncGenerator[DB, None]:
    """Create an in-memory JSON database for testing."""
    import paskia.db.operations as ops_db
    from paskia.db.jsonl import JsonlStore

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=True) as f:
        db = DB()
        store = JsonlStore(db, f.name)
        db._store = store
        await store.load()
        ops_db._db = db
        ops_db._store = store
        yield db
        ops_db._db = None
        ops_db._store = None


@pytest_asyncio.fixture(scope="function")
async def passkey_instance() -> Passkey:
    """Initialize a passkey instance for testing."""
    pk = Passkey(
        rp_id="localhost",
        rp_name="Test RP",
        origins=["http://localhost:4401"],
    )
    paskia_globals.passkey._instance = pk
    yield pk
    paskia_globals.passkey._instance = None


@pytest_asyncio.fixture(scope="function")
async def test_org(test_db: DB, admin_permission: Permission) -> Org:
    """Create a test organization with admin permission."""
    org = Org.create(display_name="Test Organization")
    create_organization(org)
    # Grant admin permission to this org
    add_permission_to_organization(org.uuid, admin_permission.uuid)
    return org


@pytest_asyncio.fixture(scope="function")
async def admin_permission(test_db: DB) -> Permission:
    """Create the auth:admin permission."""
    perm = Permission.create(scope="auth:admin", display_name="Master Admin")
    create_permission(perm)
    return perm


@pytest_asyncio.fixture(scope="function")
async def org_admin_permission(test_db: DB, test_org: Org) -> Permission:
    """Create the auth:org:admin permission."""
    perm = Permission.create(scope="auth:org:admin", display_name="Organization Admin")
    create_permission(perm)
    # Make it grantable by the org
    add_permission_to_organization(test_org.uuid, perm.uuid)
    return perm


@pytest_asyncio.fixture(scope="function")
async def test_role(
    test_db: DB,
    test_org: Org,
    admin_permission: Permission,
    org_admin_permission: Permission,
) -> Role:
    """Create a test role with admin permission."""
    role = Role.create(
        org=test_org.uuid,
        display_name="Test Admin Role",
        permissions={admin_permission.uuid, org_admin_permission.uuid},
    )
    create_role(role)
    return role


@pytest_asyncio.fixture(scope="function")
async def user_role(test_db: DB, test_org: Org) -> Role:
    """Create a test role without admin permission (regular user)."""
    role = Role.create(
        org=test_org.uuid,
        display_name="User Role",
    )
    create_role(role)
    return role


@pytest_asyncio.fixture(scope="function")
async def test_user(test_db: DB, test_role: Role) -> User:
    """Create a test user with admin role."""
    user = User.create(
        display_name="Test Admin",
        role=test_role.uuid,
    )
    create_user(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def regular_user(test_db: DB, user_role: Role) -> User:
    """Create a regular test user without admin permissions."""
    user = User.create(
        display_name="Regular User",
        role=user_role.uuid,
    )
    create_user(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def test_credential(test_db: DB, test_user: User) -> Credential:
    """Create a test credential for the admin user."""
    credential = Credential.create(
        credential_id=os.urandom(32),
        user=test_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
    )
    create_credential(credential)
    return credential


@pytest_asyncio.fixture(scope="function")
async def regular_credential(test_db: DB, regular_user: User) -> Credential:
    """Create a test credential for the regular user."""
    credential = Credential.create(
        credential_id=os.urandom(32),
        user=regular_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
    )
    create_credential(credential)
    return credential


@pytest_asyncio.fixture(scope="function")
async def session_token(
    test_db: DB, test_user: User, test_credential: Credential
) -> str:
    """Create a session for the admin user and return the token."""
    token = _create_token()
    create_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        key=token,
        host="localhost:4401",
        ip="127.0.0.1",
        user_agent="pytest",
        expiry=expires(),
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def regular_session_token(
    test_db: DB, regular_user: User, regular_credential: Credential
) -> str:
    """Create a session for a regular user and return the token."""
    token = _create_token()
    create_session(
        user_uuid=regular_user.uuid,
        credential_uuid=regular_credential.uuid,
        key=token,
        host="localhost:4401",
        ip="127.0.0.1",
        user_agent="pytest",
        expiry=expires(),
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def reset_token(test_db: DB, test_user: User, test_credential: Credential) -> str:
    """Create a reset token for the test user."""
    from paskia.authsession import reset_expires
    from paskia.util.passphrase import generate

    token = generate()
    create_reset_token(
        user_uuid=test_user.uuid,
        passphrase=token,
        expiry=reset_expires(),
        token_type="reset",
    )
    return token


@pytest_asyncio.fixture(scope="function")
async def client(
    test_db: DB, passkey_instance: Passkey
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an async test client for the FastAPI app.

    Note: We import the app inside the fixture to ensure globals are
    initialized first.
    """
    # Import app after globals are set
    from paskia.fastapi.mainapp import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://localhost:4401",
    ) as client:
        yield client


def auth_headers(token: str) -> dict[str, str]:
    """Return headers with auth cookie set."""
    return {"Cookie": f"{AUTH_COOKIE_NAME}={token}"}


def auth_cookie(token: str) -> httpx.Cookies:
    """Return cookies dict with auth cookie."""
    cookies = httpx.Cookies()
    cookies.set(AUTH_COOKIE_NAME, token, domain="localhost")
    return cookies
