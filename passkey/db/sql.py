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
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from . import Credential, DatabaseInterface, Session, User, db

DB_PATH = "sqlite+aiosqlite:///webauthn.db"


async def init(*args, **kwargs):
    db.instance = DB()
    await db.instance.init_db()


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


class DB(DatabaseInterface):
    """Database class that handles its own connections."""

    def __init__(self, db_path: str = DB_PATH):
        """Initialize with database path."""
        self.engine = create_async_engine(db_path, echo=False)
        self.async_session_factory = async_sessionmaker(
            self.engine, expire_on_commit=False
        )

    @asynccontextmanager
    async def session(self):
        """Async context manager that provides a database session with transaction."""
        async with self.async_session_factory() as session:
            async with session.begin():
                yield session
                await session.flush()
            await session.commit()

    async def init_db(self) -> None:
        """Initialize database tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def get_user_by_user_uuid(self, user_uuid: UUID) -> User:
        async with self.session() as session:
            stmt = select(UserModel).where(UserModel.user_uuid == user_uuid.bytes)
            result = await session.execute(stmt)
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
        async with self.session() as session:
            user_model = UserModel(
                user_uuid=user.user_uuid.bytes,
                user_name=user.user_name,
                created_at=user.created_at or datetime.now(),
                last_seen=user.last_seen,
                visits=user.visits,
            )
            session.add(user_model)

    async def create_credential(self, credential: Credential) -> None:
        async with self.session() as session:
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
            session.add(credential_model)

    async def get_credential_by_id(self, credential_id: bytes) -> Credential:
        async with self.session() as session:
            stmt = select(CredentialModel).where(
                CredentialModel.credential_id == credential_id
            )
            result = await session.execute(stmt)
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
        async with self.session() as session:
            stmt = select(CredentialModel.credential_id).where(
                CredentialModel.user_uuid == user_uuid.bytes
            )
            result = await session.execute(stmt)
            return [row[0] for row in result.fetchall()]

    async def update_credential(self, credential: Credential) -> None:
        async with self.session() as session:
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
            await session.execute(stmt)

    async def login(self, user_uuid: UUID, credential: Credential) -> None:
        async with self.session() as session:
            # Update credential
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
            await session.execute(stmt)

            # Update user's last_seen and increment visits
            stmt = (
                update(UserModel)
                .where(UserModel.user_uuid == user_uuid.bytes)
                .values(last_seen=credential.last_used, visits=UserModel.visits + 1)
            )
            await session.execute(stmt)

    async def create_user_and_credential(
        self, user: User, credential: Credential
    ) -> None:
        async with self.session() as session:
            # Set visits to 1 for the new user since they're creating their first session
            user.visits = 1

            # Create user
            user_model = UserModel(
                user_uuid=user.user_uuid.bytes,
                user_name=user.user_name,
                created_at=user.created_at or datetime.now(),
                last_seen=user.last_seen,
                visits=user.visits,
            )
            session.add(user_model)

            # Create credential
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
            session.add(credential_model)

    async def delete_credential(self, uuid: UUID, user_uuid: UUID) -> None:
        async with self.session() as session:
            stmt = (
                delete(CredentialModel)
                .where(CredentialModel.uuid == uuid.bytes)
                .where(CredentialModel.user_uuid == user_uuid.bytes)
            )
            await session.execute(stmt)

    async def create_session(
        self,
        user_uuid: UUID,
        key: bytes,
        expires: datetime,
        info: dict,
        credential_uuid: UUID | None = None,
    ) -> None:
        async with self.session() as session:
            session_model = SessionModel(
                key=key,
                user_uuid=user_uuid.bytes,
                credential_uuid=credential_uuid.bytes if credential_uuid else None,
                expires=expires,
                info=info,
            )
            session.add(session_model)

    async def get_session(self, key: bytes) -> Session | None:
        async with self.session() as session:
            stmt = select(SessionModel).where(SessionModel.key == key)
            result = await session.execute(stmt)
            session_model = result.scalar_one_or_none()

            if session_model:
                return Session(
                    key=session_model.key,
                    user_uuid=UUID(bytes=session_model.user_uuid),
                    credential_uuid=UUID(bytes=session_model.credential_uuid)
                    if session_model.credential_uuid
                    else None,
                    expires=session_model.expires,
                    info=session_model.info or {},
                )
            return None

    async def delete_session(self, key: bytes) -> None:
        async with self.session() as session:
            await session.execute(delete(SessionModel).where(SessionModel.key == key))

    async def update_session(self, key: bytes, expires: datetime, info: dict) -> None:
        async with self.session() as session:
            await session.execute(
                update(SessionModel)
                .where(SessionModel.key == key)
                .values(expires=expires, info=info)
            )

    async def cleanup(self) -> None:
        async with self.session() as session:
            current_time = datetime.now()
            stmt = delete(SessionModel).where(SessionModel.expires < current_time)
            await session.execute(stmt)
