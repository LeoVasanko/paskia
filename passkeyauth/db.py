"""
Async database implementation for WebAuthn passkey authentication.

This module provides an async database layer using dataclasses and aiosqlite
for managing users and credentials in a WebAuthn authentication system.
"""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import aiosqlite

from .passkey import StoredCredential

DB_PATH = "webauthn.db"

# SQL Statements
SQL_CREATE_USERS = """
    CREATE TABLE IF NOT EXISTS users (
        user_id BINARY(16) PRIMARY KEY NOT NULL,
        user_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP NULL
    )
"""

SQL_CREATE_CREDENTIALS = """
    CREATE TABLE IF NOT EXISTS credentials (
        credential_id BINARY(64) PRIMARY KEY NOT NULL,
        user_id BINARY(16) NOT NULL,
        aaguid BINARY(16) NOT NULL,
        public_key BLOB NOT NULL,
        sign_count INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP NULL,
        last_verified TIMESTAMP NULL,
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
    )
"""

SQL_GET_USER_BY_USER_ID = """
    SELECT * FROM users WHERE user_id = ?
"""

SQL_CREATE_USER = """
    INSERT INTO users (user_id, user_name, created_at, last_seen) VALUES (?, ?, ?, ?)
"""

SQL_STORE_CREDENTIAL = """
    INSERT INTO credentials (credential_id, user_id, aaguid, public_key, sign_count, created_at, last_used, last_verified)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""

SQL_GET_CREDENTIAL_BY_ID = """
    SELECT * FROM credentials WHERE credential_id = ?
"""

SQL_GET_USER_CREDENTIALS = """
    SELECT credential_id FROM credentials WHERE user_id = ?
"""

SQL_UPDATE_CREDENTIAL = """
    UPDATE credentials
    SET sign_count = ?, created_at = ?, last_used = ?, last_verified = ?
    WHERE credential_id = ?
"""

SQL_DELETE_CREDENTIAL = """
    DELETE FROM credentials WHERE credential_id = ?
"""


@dataclass
class User:
    user_id: UUID
    user_name: str
    created_at: datetime | None = None
    last_seen: datetime | None = None


@asynccontextmanager
async def connect():
    conn = await aiosqlite.connect(DB_PATH)
    try:
        yield DB(conn)
        await conn.commit()
    finally:
        await conn.close()


class DB:
    def __init__(self, conn: aiosqlite.Connection):
        self.conn = conn

    async def init_db(self) -> None:
        """Initialize database tables."""
        await self.conn.execute(SQL_CREATE_USERS)
        await self.conn.execute(SQL_CREATE_CREDENTIALS)
        await self.conn.commit()

    # Database operation functions that work with a connection
    async def get_user_by_user_id(self, user_id: bytes) -> User:
        """Get user record by WebAuthn user ID."""
        async with self.conn.execute(SQL_GET_USER_BY_USER_ID, (user_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return User(
                    user_id=UUID(bytes=row[0]),
                    user_name=row[1],
                    created_at=_convert_datetime(row[2]),
                    last_seen=_convert_datetime(row[3]),
                )
            raise ValueError("User not found")

    async def create_user(self, user: User) -> None:
        """Create a new user and return the User dataclass."""
        await self.conn.execute(
            SQL_CREATE_USER,
            (
                user.user_id.bytes,
                user.user_name,
                user.created_at or datetime.now(),
                user.last_seen,
            ),
        )

    async def create_credential(self, credential: StoredCredential) -> None:
        """Store a credential for a user."""
        await self.conn.execute(
            SQL_STORE_CREDENTIAL,
            (
                credential.credential_id,
                credential.user_id.bytes,
                credential.aaguid.bytes,
                credential.public_key,
                credential.sign_count,
                credential.created_at,
                credential.last_used,
                credential.last_verified,
            ),
        )

    async def get_credential_by_id(self, credential_id: bytes) -> StoredCredential:
        """Get credential by credential ID."""
        async with self.conn.execute(
            SQL_GET_CREDENTIAL_BY_ID, (credential_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return StoredCredential(
                    credential_id=row[0],
                    user_id=UUID(bytes=row[1]),
                    aaguid=UUID(bytes=row[2]),
                    public_key=row[3],
                    sign_count=row[4],
                    created_at=datetime.fromisoformat(row[5]),
                    last_used=_convert_datetime(row[6]),
                    last_verified=_convert_datetime(row[7]),
                )
            raise ValueError("Credential not registered")

    async def get_credentials_by_user_id(self, user_id: bytes) -> list[bytes]:
        """Get all credential IDs for a user."""
        async with self.conn.execute(SQL_GET_USER_CREDENTIALS, (user_id,)) as cursor:
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    async def update_credential(self, credential: StoredCredential) -> None:
        """Update the sign count, created_at, last_used, and last_verified for a credential."""
        await self.conn.execute(
            SQL_UPDATE_CREDENTIAL,
            (
                credential.sign_count,
                credential.created_at,
                credential.last_used,
                credential.last_verified,
                credential.credential_id,
            ),
        )

    async def login(self, user_id: bytes, credential: StoredCredential) -> None:
        """Update the last_seen timestamp for a user and the credential record used for logging in."""
        await self.conn.execute("BEGIN")
        await self.update_credential(credential)
        await self.conn.execute(
            "UPDATE users SET last_seen = ? WHERE user_id = ?",
            (credential.last_used, user_id),
        )

    async def delete_credential(self, credential_id: bytes) -> None:
        """Delete a credential by its ID."""
        await self.conn.execute(SQL_DELETE_CREDENTIAL, (credential_id,))
        await self.conn.commit()


def _convert_datetime(val):
    """Convert string from SQLite to datetime object (pass through None)."""
    return val and datetime.fromisoformat(val)
