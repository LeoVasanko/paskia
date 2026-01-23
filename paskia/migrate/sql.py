"""
Legacy SQL database implementation for migration purposes.

This module provides the async SQLAlchemy database layer that was used
before the JSONL format. It is kept here for migration purposes only.

DO NOT use this module for new code. Use paskia.db.json instead.
"""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    event,
    select,
)
from sqlalchemy.dialects.sqlite import BLOB
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from paskia.db import (
    Credential,
    Org,
    ResetToken,
    Role,
    User,
)


# Local Permission class for SQL schema (uses 'id' not 'uuid' + 'scope')
@dataclass
class SqlPermission:
    """Permission as stored in the old SQL schema with id field."""

    id: str
    display_name: str


DB_PATH_DEFAULT = "sqlite+aiosqlite:///paskia.sqlite"


# Local Session class for SQL schema (uses 'renewed' not 'expiry')
@dataclass
class _SqlSession:
    """Session as stored in the old SQL schema with renewed timestamp."""

    key: bytes
    user_uuid: UUID
    credential_uuid: UUID
    host: str
    ip: str
    user_agent: str
    renewed: datetime


def _normalize_dt(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


class OrgModel(Base):
    __tablename__ = "orgs"

    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)

    def as_dataclass(self):
        # Base Org without permissions/roles (filled by data accessors)
        return Org(UUID(bytes=self.uuid), self.display_name)

    @staticmethod
    def from_dataclass(org: Org):
        return OrgModel(uuid=org.uuid.bytes, display_name=org.display_name)


class RoleModel(Base):
    __tablename__ = "roles"

    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    org_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("orgs.uuid", ondelete="CASCADE"), nullable=False
    )
    display_name: Mapped[str] = mapped_column(String, nullable=False)

    def as_dataclass(self):
        # Base Role without permissions (filled by data accessors)
        return Role(
            uuid=UUID(bytes=self.uuid),
            org_uuid=UUID(bytes=self.org_uuid),
            display_name=self.display_name,
        )

    @staticmethod
    def from_dataclass(role: Role):
        return RoleModel(
            uuid=role.uuid.bytes,
            org_uuid=role.org_uuid.bytes,
            display_name=role.display_name,
        )


class UserModel(Base):
    __tablename__ = "users"

    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    role_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("roles.uuid", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    visits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def as_dataclass(self) -> User:
        return User(
            uuid=UUID(bytes=self.uuid),
            display_name=self.display_name,
            role_uuid=UUID(bytes=self.role_uuid),
            created_at=_normalize_dt(self.created_at) or self.created_at,
            last_seen=_normalize_dt(self.last_seen) or self.last_seen,
            visits=self.visits,
        )

    @staticmethod
    def from_dataclass(user: User):
        return UserModel(
            uuid=user.uuid.bytes,
            display_name=user.display_name,
            role_uuid=user.role_uuid.bytes,
            created_at=user.created_at or datetime.now(timezone.utc),
            last_seen=user.last_seen,
            visits=user.visits,
        )


class CredentialModel(Base):
    __tablename__ = "credentials"

    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    credential_id: Mapped[bytes] = mapped_column(
        LargeBinary(64), unique=True, index=True
    )
    user_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.uuid", ondelete="CASCADE")
    )
    aaguid: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    public_key: Mapped[bytes] = mapped_column(BLOB, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_used: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_verified: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def as_dataclass(self):
        return Credential(
            uuid=UUID(bytes=self.uuid),
            credential_id=self.credential_id,
            user_uuid=UUID(bytes=self.user_uuid),
            aaguid=UUID(bytes=self.aaguid),
            public_key=self.public_key,
            sign_count=self.sign_count,
            created_at=_normalize_dt(self.created_at) or self.created_at,
            last_used=_normalize_dt(self.last_used) or self.last_used,
            last_verified=_normalize_dt(self.last_verified) or self.last_verified,
        )


class SessionModel(Base):
    __tablename__ = "sessions"

    key: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    user_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.uuid", ondelete="CASCADE"), nullable=False
    )
    credential_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16),
        ForeignKey("credentials.uuid", ondelete="CASCADE"),
        nullable=False,
    )
    host: Mapped[str] = mapped_column(String, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=False)
    renewed: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def as_dataclass(self):
        return _SqlSession(
            key=self.key,
            user_uuid=UUID(bytes=self.user_uuid),
            credential_uuid=UUID(bytes=self.credential_uuid),
            host=self.host,
            ip=self.ip,
            user_agent=self.user_agent,
            renewed=_normalize_dt(self.renewed) or self.renewed,
        )

    @staticmethod
    def from_dataclass(session: _SqlSession):
        return SessionModel(
            key=session.key,
            user_uuid=session.user_uuid.bytes,
            credential_uuid=session.credential_uuid.bytes,
            host=session.host,
            ip=session.ip,
            user_agent=session.user_agent,
            renewed=session.renewed,
        )


class ResetTokenModel(Base):
    __tablename__ = "reset_tokens"

    key: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    user_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.uuid", ondelete="CASCADE"), nullable=False
    )
    token_type: Mapped[str] = mapped_column(String, nullable=False)
    expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def as_dataclass(self) -> ResetToken:
        return ResetToken(
            key=self.key,
            user_uuid=UUID(bytes=self.user_uuid),
            token_type=self.token_type,
            expiry=_normalize_dt(self.expiry) or self.expiry,
        )


class PermissionModel(Base):
    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)

    def as_dataclass(self):
        return SqlPermission(self.id, self.display_name)

    @staticmethod
    def from_dataclass(permission: SqlPermission):
        return PermissionModel(
            id=permission.id,
            display_name=permission.display_name,
        )


class OrgPermission(Base):
    """Permissions each organization is allowed to grant to its roles."""

    __tablename__ = "org_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    org_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("orgs.uuid", ondelete="CASCADE")
    )
    permission_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("permissions.id", ondelete="CASCADE")
    )


class RolePermission(Base):
    """Permissions that each role grants to its members."""

    __tablename__ = "role_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    role_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("roles.uuid", ondelete="CASCADE")
    )
    permission_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("permissions.id", ondelete="CASCADE")
    )


class DB:
    """Legacy SQL database class for migration purposes only."""

    def __init__(self, db_path: str = DB_PATH_DEFAULT):
        """Initialize with database path."""
        self.engine = create_async_engine(db_path, echo=False)
        # Ensure SQLite foreign key enforcement is ON for every new connection
        if db_path.startswith("sqlite"):

            @event.listens_for(self.engine.sync_engine, "connect")
            def _fk_on(dbapi_connection, connection_record):
                try:
                    cursor = dbapi_connection.cursor()
                    cursor.execute("PRAGMA foreign_keys=ON;")
                    cursor.close()
                except Exception:
                    pass

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

    async def list_permissions(self) -> list[SqlPermission]:
        async with self.session() as session:
            result = await session.execute(select(PermissionModel))
            return [p.as_dataclass() for p in result.scalars().all()]

    async def list_organizations(self) -> list[Org]:
        async with self.session() as session:
            # Load all orgs
            orgs_result = await session.execute(select(OrgModel))
            org_models = orgs_result.scalars().all()
            if not org_models:
                return []

            # Preload org permissions mapping
            org_perms_result = await session.execute(select(OrgPermission))
            org_perms = org_perms_result.scalars().all()
            perms_by_org: dict[bytes, list[str]] = {}
            for op in org_perms:
                perms_by_org.setdefault(op.org_uuid, []).append(op.permission_id)

            # Preload roles
            roles_result = await session.execute(select(RoleModel))
            role_models = roles_result.scalars().all()

            # Preload role permissions mapping
            rp_result = await session.execute(select(RolePermission))
            rps = rp_result.scalars().all()
            perms_by_role: dict[bytes, list[str]] = {}
            for rp in rps:
                perms_by_role.setdefault(rp.role_uuid, []).append(rp.permission_id)

            # Build org dataclasses with roles and permission IDs
            roles_by_org: dict[bytes, list[Role]] = {}
            for rm in role_models:
                r_dc = rm.as_dataclass()
                r_dc.permissions = perms_by_role.get(rm.uuid, [])
                roles_by_org.setdefault(rm.org_uuid, []).append(r_dc)

            orgs: list[Org] = []
            for om in org_models:
                o_dc = om.as_dataclass()
                o_dc.permissions = perms_by_org.get(om.uuid, [])
                o_dc.roles = roles_by_org.get(om.uuid, [])
                orgs.append(o_dc)

            return orgs
