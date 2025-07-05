"""
Async database implementation for WebAuthn passkey authentication.

This module provides an async database layer using dataclasses and aiosqlite
for managing users and credentials in a WebAuthn authentication system.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import aiosqlite

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
    INSERT INTO credentials (credential_id, user_id, aaguid, public_key, sign_count)
    VALUES (?, ?, ?, ?, ?)
"""

SQL_GET_CREDENTIAL_BY_ID = """
    SELECT credential_id, user_id, aaguid, public_key, sign_count, created_at, last_used
    FROM credentials
    WHERE credential_id = ?
"""

SQL_GET_USER_CREDENTIALS = """
    SELECT c.credential_id
    FROM credentials c
    JOIN users u ON c.user_id = u.user_id
    WHERE u.user_name = ?
"""

SQL_UPDATE_CREDENTIAL_SIGN_COUNT = """
    UPDATE credentials
    SET sign_count = ?, last_used = CURRENT_TIMESTAMP
    WHERE credential_id = ?
"""


@dataclass
class User:
    """User data model."""

    user_id: bytes = b""
    user_name: str = ""
    created_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class Credential:
    """Credential data model."""

    credential_id: bytes
    user_id: bytes
    aaguid: UUID
    public_key: bytes
    sign_count: int
    created_at: datetime
    last_used: datetime | None = None


class Database:
    """Async database handler for WebAuthn operations."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    async def init_database(self):
        """Initialize the SQLite database with required tables."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(SQL_CREATE_USERS)
            await conn.execute(SQL_CREATE_CREDENTIALS)
            await conn.commit()

    async def get_user_by_user_id(self, user_id: bytes) -> User:
        """Get user record by WebAuthn user ID."""
        async with aiosqlite.connect(self.db_path) as conn:
            async with conn.execute(SQL_GET_USER_BY_USER_ID, (user_id,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return User(
                        user_id=row[0],
                        user_name=row[1],
                        created_at=row[2],
                        last_seen=row[3],
                    )
                raise ValueError("User not found")

    async def create_user(self, user: User) -> User:
        """Create a new user and return the User dataclass."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                SQL_CREATE_USER,
                (user.user_id, user.user_name, user.created_at, user.last_seen),
            )
            await conn.commit()
            return user

    async def store_credential(self, credential: Credential) -> None:
        """Store a credential for a user."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                SQL_STORE_CREDENTIAL,
                (
                    credential.credential_id,
                    credential.user_id,
                    credential.aaguid.bytes,
                    credential.public_key,
                    credential.sign_count,
                ),
            )
            await conn.commit()

    async def get_credential_by_id(self, credential_id: bytes) -> Credential:
        """Get credential by credential ID."""
        async with aiosqlite.connect(self.db_path) as conn:
            async with conn.execute(
                SQL_GET_CREDENTIAL_BY_ID, (credential_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return Credential(
                        credential_id=row[0],
                        user_id=row[1],
                        aaguid=UUID(bytes=row[2]),  # Convert bytes to UUID
                        public_key=row[3],
                        sign_count=row[4],
                        created_at=row[5],
                        last_used=row[6],
                    )
                raise ValueError("Credential not found")

    async def get_credentials_by_user_id(self, user_id: bytes) -> list[bytes]:
        """Get all credential IDs for a user."""
        async with aiosqlite.connect(self.db_path) as conn:
            async with conn.execute(SQL_GET_USER_CREDENTIALS, (user_id,)) as cursor:
                rows = await cursor.fetchall()
                return [row[0] for row in rows]

    async def update_credential(self, credential: Credential) -> None:
        """Update the sign count for a credential."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                SQL_UPDATE_CREDENTIAL_SIGN_COUNT,
                (credential.sign_count, credential.credential_id),
            )
            await conn.commit()

    async def update_user_last_seen(
        self, user_id: bytes, last_seen: datetime | None = None
    ) -> None:
        """Update the last_seen timestamp for a user."""
        if last_seen is None:
            last_seen = datetime.now()
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                "UPDATE users SET last_seen = ? WHERE user_id = ?",
                (last_seen, user_id),
            )
            await conn.commit()


# Global database instance
db = Database()
