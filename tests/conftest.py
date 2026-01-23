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
from datetime import datetime, timezone
from uuid import UUID

import httpx
import pytest
import pytest_asyncio
import uuid7

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
from paskia.db.operations import DB
from paskia.fastapi.session import AUTH_COOKIE_NAME
from paskia.sansio import Passkey
from paskia.util.tokens import create_token, session_key


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def test_db() -> AsyncGenerator[DB, None]:
    """Create an in-memory JSON database for testing.

    Uses a temp file that gets cleaned up after each test.
    """
    import paskia.db.operations as ops_db

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=True) as f:
        db = DB(f.name)
        await db.load()
        ops_db._db = db
        yield db
        # Clean up
        ops_db._db = None


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
    org = Org(
        uuid=uuid7.create(),
        display_name="Test Organization",
        permissions=["auth:admin"],  # Org can grant this permission
    )
    create_organization(org)
    return org


@pytest_asyncio.fixture(scope="function")
async def admin_permission(test_db: DB) -> Permission:
    """Create the auth:admin permission."""
    import uuid7

    perm = Permission(
        uuid=uuid7.create(), scope="auth:admin", display_name="Master Admin"
    )
    create_permission(perm)
    return perm


@pytest_asyncio.fixture(scope="function")
async def org_admin_permission(test_db: DB, test_org: Org) -> Permission:
    """Create the auth:org:admin permission."""
    import uuid7

    perm = Permission(
        uuid=uuid7.create(), scope="auth:org:admin", display_name="Organization Admin"
    )
    create_permission(perm)
    # Make it grantable by the org
    add_permission_to_organization(str(test_org.uuid), "auth:org:admin")
    return perm


@pytest_asyncio.fixture(scope="function")
async def test_role(
    test_db: DB,
    test_org: Org,
    admin_permission: Permission,
    org_admin_permission: Permission,
) -> Role:
    """Create a test role with admin permission."""
    role = Role(
        uuid=uuid7.create(),
        org_uuid=test_org.uuid,
        display_name="Test Admin Role",
        permissions=["auth:admin", "auth:org:admin"],
    )
    create_role(role)
    return role


@pytest_asyncio.fixture(scope="function")
async def user_role(test_db: DB, test_org: Org) -> Role:
    """Create a test role without admin permission (regular user)."""
    role = Role(
        uuid=uuid7.create(),
        org_uuid=test_org.uuid,
        display_name="User Role",
        permissions=[],
    )
    create_role(role)
    return role


@pytest_asyncio.fixture(scope="function")
async def test_user(test_db: DB, test_role: Role) -> User:
    """Create a test user with admin role."""
    user = User(
        uuid=uuid7.create(),
        display_name="Test Admin",
        role_uuid=test_role.uuid,
        created_at=datetime.now(timezone.utc),
        visits=0,
    )
    create_user(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def regular_user(test_db: DB, user_role: Role) -> User:
    """Create a regular test user without admin permissions."""
    user = User(
        uuid=uuid7.create(),
        display_name="Regular User",
        role_uuid=user_role.uuid,
        created_at=datetime.now(timezone.utc),
        visits=0,
    )
    create_user(user)
    return user


@pytest_asyncio.fixture(scope="function")
async def test_credential(test_db: DB, test_user: User) -> Credential:
    """Create a test credential for the admin user."""
    credential = Credential(
        uuid=uuid7.create(),
        credential_id=os.urandom(32),
        user_uuid=test_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
        created_at=datetime.now(timezone.utc),
        last_used=None,
        last_verified=None,
    )
    create_credential(credential)
    return credential


@pytest_asyncio.fixture(scope="function")
async def regular_credential(test_db: DB, regular_user: User) -> Credential:
    """Create a test credential for the regular user."""
    credential = Credential(
        uuid=uuid7.create(),
        credential_id=os.urandom(32),
        user_uuid=regular_user.uuid,
        aaguid=UUID("00000000-0000-0000-0000-000000000000"),
        public_key=os.urandom(64),
        sign_count=0,
        created_at=datetime.now(timezone.utc),
        last_used=None,
        last_verified=None,
    )
    create_credential(credential)
    return credential


@pytest_asyncio.fixture(scope="function")
async def session_token(
    test_db: DB, test_user: User, test_credential: Credential
) -> str:
    """Create a session for the admin user and return the token."""
    token = create_token()
    create_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        key=session_key(token),
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
    token = create_token()
    create_session(
        user_uuid=regular_user.uuid,
        credential_uuid=regular_credential.uuid,
        key=session_key(token),
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
    from paskia.util.tokens import reset_key

    token = generate()
    create_reset_token(
        user_uuid=test_user.uuid,
        key=reset_key(token),
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
