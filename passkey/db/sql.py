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
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ..globals import db
from . import (
    Credential,
    DatabaseInterface,
    Org,
    Permission,
    Session,
    SessionContext,
    User,
)

DB_PATH = "sqlite+aiosqlite:///passkey-auth.sqlite"


async def init(*args, **kwargs):
    db.instance = DB()
    await db.instance.init_db()


# SQLAlchemy Models
class Base(DeclarativeBase):
    pass


# Association model for many-to-many relationship between organizations and permissions
class OrgPermission(Base):
    """Permissions each Org is allowed to grant to its roles."""

    __tablename__ = "org_permissions"

    org_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16),
        ForeignKey("orgs.uuid", ondelete="CASCADE"),
        primary_key=True,
    )
    permission_id: Mapped[str] = mapped_column(
        String(32),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )


class PermissionModel(Base):
    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)


class OrgModel(Base):
    __tablename__ = "orgs"

    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class UserModel(Base):
    __tablename__ = "users"

    uuid: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)
    org_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("orgs.uuid", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    visits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    last_used: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_verified: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SessionModel(Base):
    __tablename__ = "sessions"

    key: Mapped[bytes] = mapped_column(LargeBinary(16), primary_key=True)
    user_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("users.uuid", ondelete="CASCADE")
    )
    credential_uuid: Mapped[bytes | None] = mapped_column(
        LargeBinary(16), ForeignKey("credentials.uuid", ondelete="CASCADE")
    )
    expires: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    info: Mapped[dict | None] = mapped_column(JSON, nullable=True)


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

    async def get_user_by_uuid(self, user_uuid: UUID) -> User:
        async with self.session() as session:
            stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            result = await session.execute(stmt)
            user_model = result.scalar_one_or_none()

            if user_model:
                return User(
                    uuid=UUID(bytes=user_model.uuid),
                    display_name=user_model.display_name,
                    org_uuid=UUID(bytes=user_model.org_uuid),
                    role=user_model.role,
                    created_at=user_model.created_at,
                    last_seen=user_model.last_seen,
                    visits=user_model.visits,
                )
            raise ValueError("User not found")

    async def create_user(self, user: User) -> None:
        async with self.session() as session:
            user_model = UserModel(
                uuid=user.uuid.bytes,
                display_name=user.display_name,
                org_uuid=user.org_uuid.bytes,
                role=user.role,
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
                .where(UserModel.uuid == user_uuid.bytes)
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
                uuid=user.uuid.bytes,
                display_name=user.display_name,
                org_uuid=user.org_uuid.bytes,
                role=user.role,
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

    # Organization operations
    async def create_organization(self, organization: Org) -> None:
        async with self.session() as session:
            # Convert string ID to UUID bytes for storage
            org_uuid = UUID(organization.id)
            org_model = OrgModel(
                uuid=org_uuid.bytes,
                options=organization.options,
            )
            session.add(org_model)

    async def get_organization(self, org_id: str) -> Org:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = select(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            result = await session.execute(stmt)
            org_model = result.scalar_one_or_none()

            if org_model:
                # Convert UUID bytes back to string for the interface
                return Org(
                    id=str(UUID(bytes=org_model.uuid)),
                    options=org_model.options,
                )
            raise ValueError("Organization not found")

    async def update_organization(self, organization: Org) -> None:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(organization.id)
            stmt = (
                update(OrgModel)
                .where(OrgModel.uuid == org_uuid.bytes)
                .values(options=organization.options)
            )
            await session.execute(stmt)

    async def delete_organization(self, org_id: str) -> None:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = delete(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            await session.execute(stmt)

    async def add_user_to_organization(
        self, user_uuid: UUID, org_id: str, role: str
    ) -> None:
        async with self.session() as session:
            # Get user and organization models
            user_stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            user_result = await session.execute(user_stmt)
            user_model = user_result.scalar_one_or_none()

            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            org_stmt = select(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            org_result = await session.execute(org_stmt)
            org_model = org_result.scalar_one_or_none()

            if not user_model:
                raise ValueError("User not found")
            if not org_model:
                raise ValueError("Organization not found")

            # Update the user's organization and role
            stmt = (
                update(UserModel)
                .where(UserModel.uuid == user_uuid.bytes)
                .values(org_uuid=org_uuid.bytes, role=role)
            )
            await session.execute(stmt)

    async def transfer_user_to_organization(
        self, user_uuid: UUID, new_org_id: str, new_role: str | None = None
    ) -> None:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            new_org_uuid = UUID(new_org_id)

            # Verify the new organization exists
            org_stmt = select(OrgModel).where(OrgModel.uuid == new_org_uuid.bytes)
            org_result = await session.execute(org_stmt)
            org_model = org_result.scalar_one_or_none()

            if not org_model:
                raise ValueError("Target organization not found")

            # Update the user's organization and role
            stmt = (
                update(UserModel)
                .where(UserModel.uuid == user_uuid.bytes)
                .values(org_uuid=new_org_uuid.bytes, role=new_role)
            )
            result = await session.execute(stmt)
            if result.rowcount == 0:
                raise ValueError("User not found")

    async def get_user_organization(self, user_uuid: UUID) -> tuple[Org, str]:
        async with self.session() as session:
            stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            result = await session.execute(stmt)
            user_model = result.scalar_one_or_none()

            if not user_model:
                raise ValueError("User not found")

            # Fetch the organization details
            org_stmt = select(OrgModel).where(OrgModel.uuid == user_model.org_uuid)
            org_result = await session.execute(org_stmt)
            org_model = org_result.scalar_one()

            # Convert UUID bytes back to string for the interface
            org = Org(id=str(UUID(bytes=org_model.uuid)), options=org_model.options)
            return (org, user_model.role or "")

    async def get_organization_users(self, org_id: str) -> list[tuple[User, str]]:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = select(UserModel).where(UserModel.org_uuid == org_uuid.bytes)
            result = await session.execute(stmt)
            user_models = result.scalars().all()

            # Create user objects with their roles
            user_role_pairs = []
            for user_model in user_models:
                user = User(
                    uuid=UUID(bytes=user_model.uuid),
                    display_name=user_model.display_name,
                    org_uuid=UUID(bytes=user_model.org_uuid),
                    role=user_model.role,
                    created_at=user_model.created_at,
                    last_seen=user_model.last_seen,
                    visits=user_model.visits,
                )
                user_role_pairs.append((user, user_model.role or ""))

            return user_role_pairs

    async def get_user_role_in_organization(
        self, user_uuid: UUID, org_id: str
    ) -> str | None:
        """Get a user's role in a specific organization."""
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = select(UserModel.role).where(
                UserModel.uuid == user_uuid.bytes,
                UserModel.org_uuid == org_uuid.bytes,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def update_user_role_in_organization(
        self, user_uuid: UUID, new_role: str
    ) -> None:
        """Update a user's role in their organization."""
        async with self.session() as session:
            stmt = (
                update(UserModel)
                .where(UserModel.uuid == user_uuid.bytes)
                .values(role=new_role)
            )
            result = await session.execute(stmt)
            if result.rowcount == 0:
                raise ValueError("User not found")

    # Permission operations
    async def create_permission(self, permission: Permission) -> None:
        async with self.session() as session:
            permission_model = PermissionModel(
                id=permission.id,
                display_name=permission.display_name,
            )
            session.add(permission_model)

    async def get_permission(self, permission_id: str) -> Permission:
        async with self.session() as session:
            stmt = select(PermissionModel).where(PermissionModel.id == permission_id)
            result = await session.execute(stmt)
            permission_model = result.scalar_one_or_none()

            if permission_model:
                return Permission(
                    id=permission_model.id,
                    display_name=permission_model.display_name,
                )
            raise ValueError("Permission not found")

    async def update_permission(self, permission: Permission) -> None:
        async with self.session() as session:
            stmt = (
                update(PermissionModel)
                .where(PermissionModel.id == permission.id)
                .values(display_name=permission.display_name)
            )
            await session.execute(stmt)

    async def delete_permission(self, permission_id: str) -> None:
        async with self.session() as session:
            stmt = delete(PermissionModel).where(PermissionModel.id == permission_id)
            await session.execute(stmt)

    async def add_permission_to_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        async with self.session() as session:
            # Get organization and permission models
            org_uuid = UUID(org_id)
            org_stmt = select(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            org_result = await session.execute(org_stmt)
            org_model = org_result.scalar_one_or_none()

            permission_stmt = select(PermissionModel).where(
                PermissionModel.id == permission_id
            )
            permission_result = await session.execute(permission_stmt)
            permission_model = permission_result.scalar_one_or_none()

            if not org_model:
                raise ValueError("Organization not found")
            if not permission_model:
                raise ValueError("Permission not found")

            # Create the org-permission relationship
            org_permission = OrgPermission(
                org_uuid=org_uuid.bytes, permission_id=permission_id
            )
            session.add(org_permission)

    async def remove_permission_from_organization(
        self, org_id: str, permission_id: str
    ) -> None:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            # Delete the org-permission relationship
            stmt = delete(OrgPermission).where(
                OrgPermission.org_uuid == org_uuid.bytes,
                OrgPermission.permission_id == permission_id,
            )
            await session.execute(stmt)

    async def get_organization_permissions(self, org_id: str) -> list[Permission]:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = select(OrgPermission).where(OrgPermission.org_uuid == org_uuid.bytes)
            result = await session.execute(stmt)
            org_permission_models = result.scalars().all()

            # Fetch the permission details for each org-permission relationship
            permissions = []
            for org_permission in org_permission_models:
                permission_stmt = select(PermissionModel).where(
                    PermissionModel.id == org_permission.permission_id
                )
                permission_result = await session.execute(permission_stmt)
                permission_model = permission_result.scalar_one()

                permission = Permission(
                    id=permission_model.id,
                    display_name=permission_model.display_name,
                )
                permissions.append(permission)

            return permissions

    async def get_permission_organizations(self, permission_id: str) -> list[Org]:
        async with self.session() as session:
            stmt = select(OrgPermission).where(
                OrgPermission.permission_id == permission_id
            )
            result = await session.execute(stmt)
            org_permission_models = result.scalars().all()

            # Fetch the organization details for each org-permission relationship
            organizations = []
            for org_permission in org_permission_models:
                org_stmt = select(OrgModel).where(
                    OrgModel.uuid == org_permission.org_uuid
                )
                org_result = await session.execute(org_stmt)
                org_model = org_result.scalar_one()

                # Convert UUID bytes back to string for the interface
                org = Org(id=str(UUID(bytes=org_model.uuid)), options=org_model.options)
                organizations.append(org)

            return organizations

    async def cleanup(self) -> None:
        async with self.session() as session:
            current_time = datetime.now()
            stmt = delete(SessionModel).where(SessionModel.expires < current_time)
            await session.execute(stmt)

    async def get_session_context(self, session_key: bytes) -> SessionContext | None:
        """Get complete session context including user, organization, role, and permissions.

        Uses efficient JOINs to retrieve all related data in a single database query.
        """
        async with self.session() as session:
            # Build a query that joins sessions, users, organizations, org_permissions, and permissions
            stmt = (
                select(
                    SessionModel,
                    UserModel,
                    OrgModel,
                    PermissionModel,
                )
                .select_from(SessionModel)
                .join(UserModel, SessionModel.user_uuid == UserModel.uuid)
                .join(OrgModel, UserModel.org_uuid == OrgModel.uuid)
                .outerjoin(OrgPermission, OrgModel.uuid == OrgPermission.org_uuid)
                .outerjoin(
                    PermissionModel, OrgPermission.permission_id == PermissionModel.id
                )
                .where(SessionModel.key == session_key)
            )

            result = await session.execute(stmt)
            rows = result.fetchall()

            if not rows:
                return None

            # Extract the first row to get session and user data
            first_row = rows[0]
            session_model, user_model, org_model, _ = first_row

            # Create the session object
            session_obj = Session(
                key=session_model.key,
                user_uuid=UUID(bytes=session_model.user_uuid),
                credential_uuid=UUID(bytes=session_model.credential_uuid)
                if session_model.credential_uuid
                else None,
                expires=session_model.expires,
                info=session_model.info or {},
            )

            # Create the user object
            user_obj = User(
                uuid=UUID(bytes=user_model.uuid),
                display_name=user_model.display_name,
                org_uuid=UUID(bytes=user_model.org_uuid),
                role=user_model.role,
                created_at=user_model.created_at,
                last_seen=user_model.last_seen,
                visits=user_model.visits,
            )

            # Create organization object (always exists now)
            organization = Org(
                id=str(UUID(bytes=org_model.uuid)),
                options=org_model.options,
            )

            # Collect all unique permissions
            permissions = []
            seen_permission_ids = set()
            for row in rows:
                _, _, _, permission_model = row
                if permission_model and permission_model.id not in seen_permission_ids:
                    permissions.append(
                        Permission(
                            id=permission_model.id,
                            display_name=permission_model.display_name,
                        )
                    )
                    seen_permission_ids.add(permission_model.id)

            return SessionContext(
                session=session_obj,
                user=user_obj,
                organization=organization,
                role=user_model.role,
                permissions=permissions if permissions else None,
            )
