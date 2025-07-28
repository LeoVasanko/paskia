"""
Async database implementation for WebAuthn passkey authentication.

This module provides an async database layer using SQLAlchemy async mode
for managing users and credentials in a WebAuthn authentication system.
"""

import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    delete,
    select,
    update,
)
from sqlalchemy.dialects.sqlite import BLOB, JSON
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ..sansio import StoredCredential

DB_PATH = "sqlite+aiosqlite:///webauthn.db"


# SQLAlchemy Models
class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    user_id: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    user_name: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    visits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationship to credentials
    credentials: Mapped[list["CredentialModel"]] = relationship(
        "CredentialModel", back_populates="user", cascade="all, delete-orphan"
    )


class CredentialModel(Base):
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    credential_id: Mapped[bytes] = mapped_column(LargeBinary(64), unique=True)
    user_id: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.user_id", ondelete="CASCADE")
    )
    aaguid: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    public_key: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    last_used: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_verified: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Relationship to user
    user: Mapped["UserModel"] = relationship("UserModel", back_populates="credentials")


class SessionModel(Base):
    __tablename__ = "sessions"

    token: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.user_id", ondelete="CASCADE")
    )
    credential_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("credentials.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    info: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Relationship to user
    user: Mapped["UserModel"] = relationship("UserModel")


@dataclass
class User:
    user_id: UUID
    user_name: str
    created_at: datetime | None = None
    last_seen: datetime | None = None
    visits: int = 0


# Global engine and session factory
engine = create_async_engine(DB_PATH, echo=False)
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


@asynccontextmanager
async def connect():
    """Context manager for database connections."""
    async with async_session_factory() as session:
        yield DB(session)
        await session.commit()


class DB:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def init_db(self) -> None:
        """Initialize database tables."""
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get_user_by_user_id(self, user_id: UUID) -> User:
        """Get user record by WebAuthn user ID."""
        stmt = select(UserModel).where(UserModel.user_id == user_id.bytes)
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        if user_model:
            return User(
                user_id=UUID(bytes=user_model.user_id),
                user_name=user_model.user_name,
                created_at=user_model.created_at,
                last_seen=user_model.last_seen,
                visits=user_model.visits,
            )
        raise ValueError("User not found")

    async def create_user(self, user: User) -> None:
        """Create a new user."""
        user_model = UserModel(
            user_id=user.user_id.bytes,
            user_name=user.user_name,
            created_at=user.created_at or datetime.now(),
            last_seen=user.last_seen,
            visits=user.visits,
        )
        self.session.add(user_model)
        await self.session.flush()

    async def create_credential(self, credential: StoredCredential) -> None:
        """Store a credential for a user."""
        credential_model = CredentialModel(
            credential_id=credential.credential_id,
            user_id=credential.user_id.bytes,
            aaguid=credential.aaguid.bytes,
            public_key=credential.public_key,
            sign_count=credential.sign_count,
            created_at=credential.created_at,
            last_used=credential.last_used,
            last_verified=credential.last_verified,
        )
        self.session.add(credential_model)
        await self.session.flush()

    async def get_credential_by_id(self, credential_id: bytes) -> StoredCredential:
        """Get credential by credential ID."""
        stmt = select(CredentialModel).where(
            CredentialModel.credential_id == credential_id
        )
        result = await self.session.execute(stmt)
        credential_model = result.scalar_one_or_none()

        if credential_model:
            return StoredCredential(
                credential_id=credential_model.credential_id,
                user_id=UUID(bytes=credential_model.user_id),
                aaguid=UUID(bytes=credential_model.aaguid),
                public_key=credential_model.public_key,
                sign_count=credential_model.sign_count,
                created_at=credential_model.created_at,
                last_used=credential_model.last_used,
                last_verified=credential_model.last_verified,
            )
        raise ValueError("Credential not registered")

    async def get_credentials_by_user_id(self, user_id: UUID) -> list[bytes]:
        """Get all credential IDs for a user."""
        stmt = select(CredentialModel.credential_id).where(
            CredentialModel.user_id == user_id.bytes
        )
        result = await self.session.execute(stmt)
        return [row[0] for row in result.fetchall()]

    async def update_credential(self, credential: StoredCredential) -> None:
        """Update the sign count, created_at, last_used, and last_verified for a credential."""
        stmt = (
            update(CredentialModel)
            .where(CredentialModel.credential_id == credential.credential_id)
            .values(
                sign_count=credential.sign_count,
                created_at=credential.created_at,
                last_used=credential.last_used,
                last_verified=credential.last_verified,
            )
        )
        await self.session.execute(stmt)

    async def login(self, user_id: UUID, credential: StoredCredential) -> None:
        """Update the last_seen timestamp for a user and the credential record used for logging in."""
        async with self.session.begin():
            # Update credential
            await self.update_credential(credential)

            # Update user's last_seen and increment visits
            stmt = (
                update(UserModel)
                .where(UserModel.user_id == user_id.bytes)
                .values(last_seen=credential.last_used, visits=UserModel.visits + 1)
            )
            await self.session.execute(stmt)

    async def create_new_session(
        self, user_id: UUID, credential: StoredCredential
    ) -> None:
        """Create a new session for a user by incrementing visits and updating last_seen."""
        async with self.session.begin():
            # Update credential
            await self.update_credential(credential)

            # Update user's last_seen and increment visits
            stmt = (
                update(UserModel)
                .where(UserModel.user_id == user_id.bytes)
                .values(last_seen=credential.last_used, visits=UserModel.visits + 1)
            )
            await self.session.execute(stmt)

    async def delete_credential(self, credential_id: bytes) -> None:
        """Delete a credential by its ID."""
        stmt = delete(CredentialModel).where(
            CredentialModel.credential_id == credential_id
        )
        await self.session.execute(stmt)
        await self.session.commit()

    async def get_user_by_username(self, user_name: str) -> User | None:
        """Get user by username."""
        stmt = select(UserModel).where(UserModel.user_name == user_name)
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        if user_model:
            return User(
                user_id=UUID(bytes=user_model.user_id),
                user_name=user_model.user_name,
                created_at=user_model.created_at,
                last_seen=user_model.last_seen,
                visits=user_model.visits,
            )
        return None

    async def create_session(
        self,
        user_id: UUID,
        credential_id: int | None = None,
        token: str | None = None,
        info: dict | None = None,
    ) -> str:
        """Create a new authentication session for a user. If credential_id is None, creates a session without a specific credential."""
        if token is None:
            token = secrets.token_urlsafe(12)

        session_model = SessionModel(
            token=token,
            user_id=user_id.bytes,
            credential_id=credential_id,
            created_at=datetime.now(),
            info=info,
        )
        self.session.add(session_model)
        await self.session.flush()
        return token

    async def create_session_by_credential_id(
        self,
        user_id: UUID,
        credential_id: bytes | None,
        token: str | None = None,
        info: dict | None = None,
    ) -> str:
        """Create a new authentication session for a user using WebAuthn credential ID. If credential_id is None, creates a session without a specific credential."""
        if credential_id is None:
            return await self.create_session(user_id, None, token, info)

        # Get the database ID from the credential
        stmt = select(CredentialModel.id).where(
            CredentialModel.credential_id == credential_id
        )
        result = await self.session.execute(stmt)
        db_credential_id = result.scalar_one()

        return await self.create_session(user_id, db_credential_id, token, info)

    async def get_session(self, token: str) -> SessionModel | None:
        """Get session by token string."""
        stmt = select(SessionModel).where(SessionModel.token == token)
        result = await self.session.execute(stmt)
        session = result.scalar_one_or_none()

        if session:
            # Check if session is expired (24 hours)
            expiry_time = session.created_at + timedelta(hours=24)
            if datetime.now() > expiry_time:
                # Clean up expired session
                await self.delete_session(token)
                return None

            return session
        return None

    async def delete_session(self, token: str) -> None:
        """Delete a session by token."""
        stmt = delete(SessionModel).where(SessionModel.token == token)
        await self.session.execute(stmt)

    async def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions (older than 24 hours)."""
        expiry_time = datetime.now() - timedelta(hours=24)
        stmt = delete(SessionModel).where(SessionModel.created_at < expiry_time)
        await self.session.execute(stmt)

    async def refresh_session(self, token: str) -> str | None:
        """Refresh a session by updating its created_at timestamp."""
        session = await self.get_session(token)
        if not session:
            return None

        # Delete old session
        await self.delete_session(token)

        # Create new session with same user and credential
        return await self.create_session(
            user_id=UUID(bytes=session.user_id),
            credential_id=session.credential_id,
            info=session.info,
        )


# Standalone functions that handle database connections internally
async def init_database() -> None:
    """Initialize database tables."""
    async with connect() as db:
        await db.init_db()


async def create_user_and_credential(user: User, credential: StoredCredential) -> None:
    """Create a new user and their first credential in a single transaction."""
    async with connect() as db:
        await db.session.begin()
        # Set visits to 1 for the new user since they're creating their first session
        user.visits = 1
        await db.create_user(user)
        await db.create_credential(credential)


async def get_user_by_id(user_id: UUID) -> User:
    """Get user record by WebAuthn user ID."""
    async with connect() as db:
        return await db.get_user_by_user_id(user_id)


async def create_credential_for_user(credential: StoredCredential) -> None:
    """Store a credential for an existing user."""
    async with connect() as db:
        await db.create_credential(credential)


async def get_credential_by_id(credential_id: bytes) -> StoredCredential:
    """Get credential by credential ID."""
    async with connect() as db:
        return await db.get_credential_by_id(credential_id)


async def get_user_credentials(user_id: UUID) -> list[bytes]:
    """Get all credential IDs for a user."""
    async with connect() as db:
        return await db.get_credentials_by_user_id(user_id)


async def login_user(user_id: UUID, credential: StoredCredential) -> None:
    """Update the last_seen timestamp for a user and the credential record used for logging in."""
    async with connect() as db:
        await db.login(user_id, credential)


async def delete_user_credential(credential_id: bytes) -> None:
    """Delete a credential by its ID."""
    async with connect() as db:
        await db.delete_credential(credential_id)


async def create_new_session(user_id: UUID, credential: StoredCredential) -> None:
    """Create a new session for a user by incrementing visits and updating last_seen."""
    async with connect() as db:
        await db.create_new_session(user_id, credential)


async def get_user_by_username(user_name: str) -> User | None:
    """Get user by username."""
    async with connect() as db:
        return await db.get_user_by_username(user_name)


async def create_session(
    user_id: UUID,
    credential_id: int | None = None,
    token: str | None = None,
    info: dict | None = None,
) -> str:
    """Create a new authentication session for a user. If credential_id is None, creates a session without a specific credential."""
    async with connect() as db:
        return await db.create_session(user_id, credential_id, token, info)


async def create_session_by_credential_id(
    user_id: UUID,
    credential_id: bytes | None,
    token: str | None = None,
    info: dict | None = None,
) -> str:
    """Create a new authentication session for a user using WebAuthn credential ID. If credential_id is None, creates a session without a specific credential."""
    async with connect() as db:
        return await db.create_session_by_credential_id(
            user_id, credential_id, token, info
        )


async def get_session(token: str) -> SessionModel | None:
    """Get session by token string."""
    async with connect() as db:
        return await db.get_session(token)


async def delete_session(token: str) -> None:
    """Delete a session by token."""
    async with connect() as db:
        await db.delete_session(token)


async def cleanup_expired_sessions() -> None:
    """Remove expired sessions (older than 24 hours)."""
    async with connect() as db:
        await db.cleanup_expired_sessions()


async def refresh_session(token: str) -> str | None:
    """Refresh a session by updating its created_at timestamp."""
    async with connect() as db:
        return await db.refresh_session(token)
