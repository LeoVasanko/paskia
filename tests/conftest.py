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

import paskia.db.operations as ops_db
from paskia import globals as paskia_globals
from paskia.authsession import reset_expires
from paskia.db import (
    Credential,
    Org,
    Permission,
    Role,
    User,
    create_credential,
    create_reset_token,
    create_role,
    create_session,
    create_user,
)
from paskia.db.jsonl import JsonlStore
from paskia.db.operations import DB
from paskia.fastapi.mainapp import app
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
    """Create an in-memory JSON database for testing.

    Uses bootstrap() to properly initialize the database with:
    - auth:admin and auth:org:admin permissions
    - A default organization with Administration role
    - An admin user with the Administration role
    """

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=True) as f:
        db = DB()
        store = JsonlStore(db, f.name)
        db._store = store
        await store.load()
        ops_db._db = db
        ops_db._store = store
        # Bootstrap creates the initial permissions, org, role, and admin user
        ops_db.bootstrap(
            org_name="Test Organization",
            admin_name="Test Admin",
        )
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
async def admin_permission(test_db: DB) -> Permission:
    """Get the auth:admin permission created by bootstrap."""
    return next(p for p in test_db.permissions.values() if p.scope == "auth:admin")


@pytest_asyncio.fixture(scope="function")
async def org_admin_permission(test_db: DB) -> Permission:
    """Get the auth:org:admin permission created by bootstrap."""
    return next(p for p in test_db.permissions.values() if p.scope == "auth:org:admin")


@pytest_asyncio.fixture(scope="function")
async def test_org(test_db: DB) -> Org:
    """Get the test organization created by bootstrap."""
    # Bootstrap creates exactly one org
    return next(iter(test_db.orgs.values()))


@pytest_asyncio.fixture(scope="function")
async def test_role(test_db: DB) -> Role:
    """Get the Administration role created by bootstrap."""
    # Bootstrap creates exactly one role (Administration)
    return next(iter(test_db.roles.values()))


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
async def test_user(test_db: DB) -> User:
    """Get the admin user created by bootstrap."""
    # Bootstrap creates exactly one user (admin)
    return next(iter(test_db.users.values()))


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
    return create_session(
        user_uuid=test_user.uuid,
        credential_uuid=test_credential.uuid,
        host="localhost",
        ip="127.0.0.1",
        user_agent="pytest",
    )


@pytest_asyncio.fixture(scope="function")
async def regular_session_token(
    test_db: DB, regular_user: User, regular_credential: Credential
) -> str:
    """Create a session for a regular user and return the token."""
    return create_session(
        user_uuid=regular_user.uuid,
        credential_uuid=regular_credential.uuid,
        host="localhost",
        ip="127.0.0.1",
        user_agent="pytest",
    )


@pytest_asyncio.fixture(scope="function")
async def reset_token(test_db: DB, test_user: User, test_credential: Credential) -> str:
    """Create a reset token for the test user."""
    return create_reset_token(
        user_uuid=test_user.uuid,
        expiry=reset_expires(),
        token_type="reset",
    )


@pytest_asyncio.fixture(scope="function")
async def client(
    test_db: DB, passkey_instance: Passkey
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Create an async test client for the FastAPI app.

    Note: We import the app inside the fixture to ensure globals are
    initialized first.
    """
    # Import app after globals are set

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
