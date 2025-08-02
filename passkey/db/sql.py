"""
Async database implementation for WebAuthn passkey authentication.

This module provides an async database layer using SQLAlchemy async mode
for managing users and credentials in a WebAuthn authentication system.
"""

from contextlib import asynccontextmanager
from datetime import datetime
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

from . import Credential, Session, User

DB_PATH = "sqlite+aiosqlite:///webauthn.db"


# SQLAlchemy Models
class Base(DeclarativeBase):
    pass


class UserModel(Base):
    __tablename__ = "users"

    user_uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
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
    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary(64), unique=True, index=True
    )
    user_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.user_uuid", ondelete="CASCADE")
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

    key: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    user_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.user_uuid", ondelete="CASCADE")
    )
    credential_uuid: Mapped[bytes | None] = mapped_column(
        LargeBinary(16), ForeignKey("credentials.uuid", ondelete="CASCADE")
    )
    expires: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    info: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Relationship to user
    user: Mapped["UserModel"] = relationship("UserModel")


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

    async def get_user_by_user_uuid(self, user_uuid: UUID) -> User:
        """Get user record by WebAuthn user UUID."""
        stmt = select(UserModel).where(UserModel.user_uuid == user_uuid.bytes)
        result = await self.session.execute(stmt)
        user_model = result.scalar_one_or_none()

        if user_model:
            return User(
                user_uuid=UUID(bytes=user_model.user_uuid),
                user_name=user_model.user_name,
                created_at=user_model.created_at,
                last_seen=user_model.last_seen,
                visits=user_model.visits,
            )
        raise ValueError("User not found")

    async def create_user(self, user: User) -> None:
        """Create a new user."""
        user_model = UserModel(
            user_uuid=user.user_uuid.bytes,
            user_name=user.user_name,
            created_at=user.created_at or datetime.now(),
            last_seen=user.last_seen,
            visits=user.visits,
        )
        self.session.add(user_model)
        await self.session.flush()

    async def create_credential(self, credential: Credential) -> None:
        """Store a credential for a user."""
        credential_model = CredentialModel(
            uuid=credential.uuid.bytes,
            credential_id=credential.credential_id,
            user_uuid=credential.user_uuid.bytes,
            aaguid=credential.aaguid.bytes,
            public_key=credential.public_key,
            sign_count=credential.sign_count,
            created_at=credential.created_at,
            last_used=credential.last_used,
            last_verified=credential.last_verified,
        )
        self.session.add(credential_model)
        await self.session.flush()

    async def get_credential_by_id(self, credential_id: bytes) -> Credential:
        """Get credential by credential ID."""
        stmt = select(CredentialModel).where(
            CredentialModel.credential_id == credential_id
        )
        result = await self.session.execute(stmt)
        credential_model = result.scalar_one_or_none()

        if not credential_model:
            raise ValueError("Credential not registered")
        return Credential(
            uuid=UUID(bytes=credential_model.uuid),
            credential_id=credential_model.credential_id,
            user_uuid=UUID(bytes=credential_model.user_uuid),
            aaguid=UUID(bytes=credential_model.aaguid),
            public_key=credential_model.public_key,
            sign_count=credential_model.sign_count,
            created_at=credential_model.created_at,
            last_used=credential_model.last_used,
            last_verified=credential_model.last_verified,
        )

    async def get_credentials_by_user_uuid(self, user_uuid: UUID) -> list[bytes]:
        """Get all credential IDs for a user."""
        stmt = select(CredentialModel.credential_id).where(
            CredentialModel.user_uuid == user_uuid.bytes
        )
        result = await self.session.execute(stmt)
        return [row[0] for row in result.fetchall()]

    async def update_credential(self, credential: Credential) -> None:
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

    async def login(self, user_uuid: UUID, credential: Credential) -> None:
        """Update the last_seen timestamp for a user and the credential record used for logging in."""
        async with self.session.begin():
            # Update credential
            await self.update_credential(credential)

            # Update user's last_seen and increment visits
            stmt = (
                update(UserModel)
                .where(UserModel.user_uuid == user_uuid.bytes)
                .values(last_seen=credential.last_used, visits=UserModel.visits + 1)
            )
            await self.session.execute(stmt)

    async def delete_credential(self, uuid: UUID, user_uuid: UUID) -> None:
        """Delete a credential by its ID."""
        stmt = (
            delete(CredentialModel)
            .where(CredentialModel.uuid == uuid.bytes)
            .where(CredentialModel.user_uuid == user_uuid.bytes)
        )
        await self.session.execute(stmt)
        await self.session.commit()

    async def create_session(
        self,
        user_uuid: UUID,
        key: bytes,
        expires: datetime,
        info: dict,
        credential_uuid: UUID | None = None,
    ) -> bytes:
        """Create a new authentication session for a user. If credential_uuid is None, creates a session without a specific credential."""
        session_model = SessionModel(
            key=key,
            user_uuid=user_uuid.bytes,
            credential_uuid=credential_uuid.bytes if credential_uuid else None,
            expires=expires,
            info=info,
        )
        self.session.add(session_model)
        await self.session.flush()
        return key

    async def get_session(self, key: bytes) -> Session | None:
        """Get session by 16-byte key."""
        stmt = select(SessionModel).where(SessionModel.key == key)
        result = await self.session.execute(stmt)
        session_model = result.scalar_one_or_none()

        if session_model:
            return Session(
                key=session_model.key,
                user_uuid=UUID(bytes=session_model.user_uuid),
                credential_uuid=UUID(bytes=session_model.credential_uuid)
                if session_model.credential_uuid
                else None,
                expires=session_model.expires,
                info=session_model.info,
            )
        return None

    async def delete_session(self, key: bytes) -> None:
        """Delete a session by 16-byte key."""
        await self.session.execute(delete(SessionModel).where(SessionModel.key == key))

    async def update_session(self, key: bytes, expires: datetime, info: dict) -> None:
        """Update session expiration time and/or info."""
        await self.session.execute(
            update(SessionModel)
            .where(SessionModel.key == key)
            .values(expires=expires, info=info)
        )

    async def cleanup_expired_sessions(self) -> None:
        """Remove expired sessions."""
        current_time = datetime.now()
        stmt = delete(SessionModel).where(SessionModel.expires < current_time)
        await self.session.execute(stmt)


# Standalone functions that handle database connections internally
async def init_database() -> None:
    """Initialize database tables."""
    async with connect() as db:
        await db.init_db()


async def create_user_and_credential(user: User, credential: Credential) -> None:
    """Create a new user and their first credential in a single transaction."""
    async with connect() as db:
        await db.session.begin()
        # Set visits to 1 for the new user since they're creating their first session
        user.visits = 1
        await db.create_user(user)
        await db.create_credential(credential)


async def get_user_by_uuid(user_uuid: UUID) -> User:
    """Get user record by WebAuthn user UUID."""
    async with connect() as db:
        return await db.get_user_by_user_uuid(user_uuid)


async def create_credential_for_user(credential: Credential) -> None:
    """Store a credential for an existing user."""
    async with connect() as db:
        await db.create_credential(credential)


async def get_credential_by_id(credential_id: bytes) -> Credential:
    """Get credential by credential ID."""
    async with connect() as db:
        return await db.get_credential_by_id(credential_id)


async def get_user_credentials(user_uuid: UUID) -> list[bytes]:
    """Get all credential IDs for a user."""
    async with connect() as db:
        return await db.get_credentials_by_user_uuid(user_uuid)


async def login_user(user_uuid: UUID, credential: Credential) -> None:
    """Update the last_seen timestamp for a user and the credential record used for logging in."""
    async with connect() as db:
        await db.login(user_uuid, credential)


async def delete_credential(uuid: UUID, user_uuid: UUID) -> None:
    """Delete a credential by its ID."""
    async with connect() as db:
        await db.delete_credential(uuid, user_uuid)


async def create_session(
    user_uuid: UUID,
    key: bytes,
    expires: datetime,
    info: dict,
    credential_uuid: UUID | None = None,
) -> bytes:
    """Create a new authentication session for a user. If credential_uuid is None, creates a session without a specific credential."""
    async with connect() as db:
        return await db.create_session(user_uuid, key, expires, info, credential_uuid)


async def get_session(key: bytes) -> Session | None:
    """Get session by 16-byte key."""
    async with connect() as db:
        return await db.get_session(key)


async def delete_session(key: bytes) -> None:
    """Delete a session by 16-byte key."""
    async with connect() as db:
        await db.delete_session(key)


async def update_session(key: bytes, expires: datetime, info: dict) -> None:
    """Update session expiration time and/or info."""
    async with connect() as db:
        await db.update_session(key, expires, info)


async def cleanup_expired_sessions() -> None:
    """Remove expired sessions."""
    async with connect() as db:
        await db.cleanup_expired_sessions()
