"""
Async database implementation for WebAuthn passkey authentication.

This module provides an async database layer using dataclasses and aiosqlite
for managing users and credentials in a WebAuthn authentication system.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import aiosqlite

DB_PATH = "webauthn.db"

# SQL Statements
SQL_CREATE_USERS = """
    CREATE TABLE IF NOT EXISTS users (
        user_id BINARY(16) PRIMARY KEY NOT NULL,
        user_name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
"""

SQL_CREATE_CREDENTIALS = """
    CREATE TABLE IF NOT EXISTS credentials (
        credential_id BINARY(64) PRIMARY KEY NOT NULL,
        user_id BINARY(16) NOT NULL,
        aaguid BINARY(16) NOT NULL,
        public_key BLOB NOT NULL,
        sign_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP NULL,
        FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
    )
"""

SQL_GET_USER_BY_USER_ID = """
    SELECT * FROM users WHERE user_id = ?
"""

SQL_CREATE_USER = """
    INSERT INTO users (user_id, user_name) VALUES (?, ?)
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


@dataclass
class Credential:
    """Credential data model."""

    credential_id: bytes = b""
    user_id: bytes = b""
    aaguid: bytes = b""
    public_key: bytes = b""
    sign_count: int = 0
    created_at: Optional[datetime] = None
    last_used: Optional[datetime] = None


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
                    return User(user_id=row[0], user_name=row[1], created_at=row[2])
                raise ValueError("User not found")

    async def create_user(self, user_id: bytes, user_name: str) -> User:
        """Create a new user and return the User dataclass."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(SQL_CREATE_USER, (user_id, user_name))
            await conn.commit()
            return User(user_id=user_id, user_name=user_name)

    async def store_credential(self, credential: Credential) -> None:
        """Store a credential for a user."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                SQL_STORE_CREDENTIAL,
                (
                    credential.credential_id,
                    credential.user_id,
                    credential.aaguid,
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
                        aaguid=row[2],
                        public_key=row[3],
                        sign_count=row[4],
                        created_at=row[5],
                        last_used=row[6],
                    )
                raise ValueError("Credential not found")

    async def update_credential(self, credential: Credential) -> None:
        """Update the sign count for a credential."""
        async with aiosqlite.connect(self.db_path) as conn:
            await conn.execute(
                SQL_UPDATE_CREDENTIAL_SIGN_COUNT,
                (credential.sign_count, credential.credential_id),
            )
            await conn.commit()


# Global database instance
db = Database()
