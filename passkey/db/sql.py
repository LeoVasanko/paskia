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
    event,
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
    Role,
    Session,
    SessionContext,
    User,
)

DB_PATH = "sqlite+aiosqlite:///passkey-auth.sqlite"


async def init(*args, **kwargs):
    db.instance = DB()
    await db.instance.init_db()


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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    visits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def as_dataclass(self) -> User:
        return User(
            uuid=UUID(bytes=self.uuid),
            display_name=self.display_name,
            role_uuid=UUID(bytes=self.role_uuid),
            created_at=self.created_at,
            last_seen=self.last_seen,
            visits=self.visits,
        )

    @staticmethod
    def from_dataclass(user: User):
        return UserModel(
            uuid=user.uuid.bytes,
            display_name=user.display_name,
            role_uuid=user.role_uuid.bytes,
            created_at=user.created_at or datetime.now(),
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
    info: Mapped[dict] = mapped_column(JSON, default=dict)

    def as_dataclass(self):
        return Session(
            key=self.key,
            user_uuid=UUID(bytes=self.user_uuid),
            credential_uuid=(
                UUID(bytes=self.credential_uuid) if self.credential_uuid else None
            ),
            expires=self.expires,
            info=self.info,
        )

    @staticmethod
    def from_dataclass(session: Session):
        return SessionModel(
            key=session.key,
            user_uuid=session.user_uuid.bytes,
            credential_uuid=session.credential_uuid and session.credential_uuid.bytes,
            expires=session.expires,
            info=session.info,
        )


class PermissionModel(Base):
    __tablename__ = "permissions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False)

    def as_dataclass(self):
        return Permission(self.id, self.display_name)

    @staticmethod
    def from_dataclass(permission: Permission):
        return PermissionModel(id=permission.id, display_name=permission.display_name)


## Join tables (no dataclass equivalents)


class OrgPermission(Base):
    """Permissions each organization is allowed to grant to its roles."""

    __tablename__ = "org_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # Not used
    org_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("orgs.uuid", ondelete="CASCADE")
    )
    permission_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("permissions.id", ondelete="CASCADE")
    )


class RolePermission(Base):
    """Permissions that each role grants to its members."""

    __tablename__ = "role_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)  # Not used
    role_uuid: Mapped[bytes] = mapped_column(
        LargeBinary(16), ForeignKey("roles.uuid", ondelete="CASCADE")
    )
    permission_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("permissions.id", ondelete="CASCADE")
    )


class DB(DatabaseInterface):
    """Database class that handles its own connections."""

    def __init__(self, db_path: str = DB_PATH):
        """Initialize with database path."""
        self.engine = create_async_engine(db_path, echo=False)
        # Ensure SQLite foreign key enforcement is ON for every new connection
        if db_path.startswith("sqlite"):

            @event.listens_for(self.engine.sync_engine, "connect")
            def _fk_on(dbapi_connection, connection_record):  # type: ignore
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

    async def get_user_by_uuid(self, user_uuid: UUID) -> User:
        async with self.session() as session:
            stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            result = await session.execute(stmt)
            user_model = result.scalar_one_or_none()

            if user_model:
                return user_model.as_dataclass()
            raise ValueError("User not found")

    async def create_user(self, user: User) -> None:
        async with self.session() as session:
            session.add(UserModel.from_dataclass(user))

    async def update_user_display_name(
        self, user_uuid: UUID, display_name: str
    ) -> None:
        async with self.session() as session:
            stmt = (
                update(UserModel)
                .where(UserModel.uuid == user_uuid.bytes)
                .values(display_name=display_name)
            )
            result = await session.execute(stmt)
            if result.rowcount == 0:  # type: ignore[attr-defined]
                raise ValueError("User not found")

    async def create_role(self, role: Role) -> None:
        async with self.session() as session:
            # Create role record
            session.add(RoleModel.from_dataclass(role))
            # Persist role permissions
            if role.permissions:
                for perm_id in role.permissions:
                    session.add(
                        RolePermission(
                            role_uuid=role.uuid.bytes,
                            permission_id=perm_id,
                        )
                    )

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
            # Create user
            user_model = UserModel.from_dataclass(user)
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

    async def create_credential_session(
        self,
        user_uuid: UUID,
        credential: Credential,
        reset_key: bytes | None,
        session_key: bytes,
        session_expires: datetime,
        session_info: dict,
        display_name: str | None = None,
    ) -> None:
        """Atomic credential + (optional old session delete) + (optional rename) + new session."""
        async with self.session() as session:
            # Insert credential
            session.add(
                CredentialModel(
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
            )
            # Delete old session if provided
            if reset_key:
                await session.execute(
                    delete(SessionModel).where(SessionModel.key == reset_key)
                )
            # Optional rename
            if display_name:
                await session.execute(
                    update(UserModel)
                    .where(UserModel.uuid == user_uuid.bytes)
                    .values(display_name=display_name)
                )
            # New session
            session.add(
                SessionModel(
                    key=session_key,
                    user_uuid=user_uuid.bytes,
                    credential_uuid=credential.uuid.bytes,
                    expires=session_expires,
                    info=session_info,
                )
            )

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
    async def create_organization(self, org: Org) -> None:
        async with self.session() as session:
            org_model = OrgModel(
                uuid=org.uuid.bytes,
                display_name=org.display_name,
            )
            session.add(org_model)
            # Persist any explicitly provided org grantable permissions
            if org.permissions:
                for perm_id in set(org.permissions):
                    session.add(
                        OrgPermission(org_uuid=org.uuid.bytes, permission_id=perm_id)
                    )

            # Automatically create an organization admin permission if not present.
            auto_perm_id = f"auth:org:{org.uuid}"
            # Only create if it does not already exist (in case caller passed it)
            existing_perm = await session.execute(
                select(PermissionModel).where(PermissionModel.id == auto_perm_id)
            )
            if not existing_perm.scalar_one_or_none():
                session.add(
                    PermissionModel(
                        id=auto_perm_id,
                        display_name=f"{org.display_name} Admin",
                    )
                )
            # Ensure org is allowed to grant its own admin permission (insert if missing)
            existing_org_perm = await session.execute(
                select(OrgPermission).where(
                    OrgPermission.org_uuid == org.uuid.bytes,
                    OrgPermission.permission_id == auto_perm_id,
                )
            )
            if not existing_org_perm.scalar_one_or_none():
                session.add(
                    OrgPermission(org_uuid=org.uuid.bytes, permission_id=auto_perm_id)
                )
            # Reflect the automatically added permission in the dataclass instance
            if auto_perm_id not in org.permissions:
                org.permissions.append(auto_perm_id)

    async def get_organization(self, org_id: str) -> Org:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = select(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            result = await session.execute(stmt)
            org_model = result.scalar_one_or_none()

            if not org_model:
                raise ValueError("Organization not found")

            # Build Org with permissions and roles
            org_dc = org_model.as_dataclass()

            # Load org permission IDs
            perm_stmt = select(OrgPermission.permission_id).where(
                OrgPermission.org_uuid == org_uuid.bytes
            )
            perm_result = await session.execute(perm_stmt)
            org_dc.permissions = [row[0] for row in perm_result.fetchall()]

            # Load roles for org
            roles_stmt = select(RoleModel).where(RoleModel.org_uuid == org_uuid.bytes)
            roles_result = await session.execute(roles_stmt)
            roles_models = roles_result.scalars().all()
            roles: list[Role] = []
            if roles_models:
                # For each role, load permission IDs
                for r_model in roles_models:
                    r_dc = r_model.as_dataclass()
                    r_perm_stmt = select(RolePermission.permission_id).where(
                        RolePermission.role_uuid == r_model.uuid
                    )
                    r_perm_result = await session.execute(r_perm_stmt)
                    r_dc.permissions = [row[0] for row in r_perm_result.fetchall()]
                    roles.append(r_dc)
            org_dc.roles = roles

            return org_dc

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

    async def update_organization(self, org: Org) -> None:
        async with self.session() as session:
            stmt = (
                update(OrgModel)
                .where(OrgModel.uuid == org.uuid.bytes)
                .values(display_name=org.display_name)
            )
            await session.execute(stmt)
            # Synchronize org permissions join table to match org.permissions
            # Delete existing rows for this org
            await session.execute(
                delete(OrgPermission).where(OrgPermission.org_uuid == org.uuid.bytes)
            )
            # Insert new rows
            if org.permissions:
                for perm_id in org.permissions:
                    await session.merge(
                        OrgPermission(org_uuid=org.uuid.bytes, permission_id=perm_id)
                    )

    async def delete_organization(self, org_uuid: UUID) -> None:
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            stmt = delete(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            await session.execute(stmt)

    async def add_user_to_organization(
        self, user_uuid: UUID, org_id: str, role: str
    ) -> None:
        async with self.session() as session:
            org_uuid = UUID(org_id)
            # Get user and organization models
            user_stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            user_result = await session.execute(user_stmt)
            user_model = user_result.scalar_one_or_none()

            # Convert string ID to UUID bytes for lookup
            org_stmt = select(OrgModel).where(OrgModel.uuid == org_uuid.bytes)
            org_result = await session.execute(org_stmt)
            org_model = org_result.scalar_one_or_none()

            if not user_model:
                raise ValueError("User not found")
            if not org_model:
                raise ValueError("Organization not found")

            # Find the role within this organization by display_name
            role_stmt = select(RoleModel).where(
                RoleModel.org_uuid == org_uuid.bytes,
                RoleModel.display_name == role,
            )
            role_result = await session.execute(role_stmt)
            role_model = role_result.scalar_one_or_none()
            if not role_model:
                raise ValueError("Role not found in organization")

            # Update the user's role assignment
            stmt = (
                update(UserModel)
                .where(UserModel.uuid == user_uuid.bytes)
                .values(role_uuid=role_model.uuid)
            )
            await session.execute(stmt)

    async def transfer_user_to_organization(
        self, user_uuid: UUID, new_org_id: str, new_role: str | None = None
    ) -> None:
        # Users are members of an org that never changes after creation.
        # Disallow transfers across organizations to enforce invariant.
        raise ValueError("Users cannot be transferred to a different organization")

    async def get_user_organization(self, user_uuid: UUID) -> tuple[Org, str]:
        async with self.session() as session:
            stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            result = await session.execute(stmt)
            user_model = result.scalar_one_or_none()

            if not user_model:
                raise ValueError("User not found")

            # Find user's role to get org
            role_stmt = select(RoleModel).where(RoleModel.uuid == user_model.role_uuid)
            role_result = await session.execute(role_stmt)
            role_model = role_result.scalar_one()

            # Fetch the organization details
            org_stmt = select(OrgModel).where(OrgModel.uuid == role_model.org_uuid)
            org_result = await session.execute(org_stmt)
            org_model = org_result.scalar_one()

            # Convert UUID bytes back to string for the interface
            return org_model.as_dataclass(), role_model.display_name

    async def get_organization_users(self, org_id: str) -> list[tuple[User, str]]:
        async with self.session() as session:
            org_uuid = UUID(org_id)
            # Join users with roles to filter by org and return role names
            stmt = (
                select(UserModel, RoleModel.display_name)
                .join(RoleModel, UserModel.role_uuid == RoleModel.uuid)
                .where(RoleModel.org_uuid == org_uuid.bytes)
            )
            result = await session.execute(stmt)
            rows = result.fetchall()
            return [(u.as_dataclass(), role_name) for (u, role_name) in rows]

    async def get_user_role_in_organization(
        self, user_uuid: UUID, org_id: str
    ) -> str | None:
        """Get a user's role in a specific organization."""
        async with self.session() as session:
            # Convert string ID to UUID bytes for lookup
            org_uuid = UUID(org_id)
            stmt = (
                select(RoleModel.display_name)
                .select_from(UserModel)
                .join(RoleModel, UserModel.role_uuid == RoleModel.uuid)
                .where(
                    UserModel.uuid == user_uuid.bytes,
                    RoleModel.org_uuid == org_uuid.bytes,
                )
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def update_user_role_in_organization(
        self, user_uuid: UUID, new_role: str
    ) -> None:
        """Update a user's role in their organization."""
        async with self.session() as session:
            # Find user's current org via their role
            user_stmt = select(UserModel).where(UserModel.uuid == user_uuid.bytes)
            user_result = await session.execute(user_stmt)
            user_model = user_result.scalar_one_or_none()
            if not user_model:
                raise ValueError("User not found")

            current_role_stmt = select(RoleModel).where(
                RoleModel.uuid == user_model.role_uuid
            )
            current_role_result = await session.execute(current_role_stmt)
            current_role = current_role_result.scalar_one()

            # Find the new role within the same organization
            role_stmt = select(RoleModel).where(
                RoleModel.org_uuid == current_role.org_uuid,
                RoleModel.display_name == new_role,
            )
            role_result = await session.execute(role_stmt)
            role_model = role_result.scalar_one_or_none()
            if not role_model:
                raise ValueError("Role not found in user's organization")

            stmt = (
                update(UserModel)
                .where(UserModel.uuid == user_uuid.bytes)
                .values(role_uuid=role_model.uuid)
            )
            await session.execute(stmt)

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

    async def rename_permission(
        self, old_id: str, new_id: str, display_name: str
    ) -> None:
        """Rename a permission's primary key and update referencing tables.

        Approach: insert new row (if id changes), update FKs, delete old row.
        Wrapped in a transaction; will raise on conflict.
        """
        if old_id == new_id:
            # Just update display name
            async with self.session() as session:
                stmt = (
                    update(PermissionModel)
                    .where(PermissionModel.id == old_id)
                    .values(display_name=display_name)
                )
                await session.execute(stmt)
            return
        async with self.session() as session:
            # Ensure old exists
            existing_old = await session.execute(
                select(PermissionModel).where(PermissionModel.id == old_id)
            )
            if not existing_old.scalar_one_or_none():
                raise ValueError("Original permission not found")

            # Check new not taken
            existing_new = await session.execute(
                select(PermissionModel).where(PermissionModel.id == new_id)
            )
            if existing_new.scalar_one_or_none():
                raise ValueError("New permission id already exists")

            # Create new permission row first
            session.add(PermissionModel(id=new_id, display_name=display_name))
            await session.flush()

            # Update org_permissions
            await session.execute(
                update(OrgPermission)
                .where(OrgPermission.permission_id == old_id)
                .values(permission_id=new_id)
            )
            await session.flush()
            # Update role_permissions
            await session.execute(
                update(RolePermission)
                .where(RolePermission.permission_id == old_id)
                .values(permission_id=new_id)
            )
            await session.flush()
            # Delete old permission row
            await session.execute(
                delete(PermissionModel).where(PermissionModel.id == old_id)
            )
            await session.flush()

    async def delete_permission(self, permission_id: str) -> None:
        async with self.session() as session:
            stmt = delete(PermissionModel).where(PermissionModel.id == permission_id)
            await session.execute(stmt)

    async def list_permissions(self) -> list[Permission]:
        async with self.session() as session:
            result = await session.execute(select(PermissionModel))
            return [p.as_dataclass() for p in result.scalars().all()]

    async def add_permission_to_role(self, role_uuid: UUID, permission_id: str) -> None:
        async with self.session() as session:
            # Ensure role exists
            role_stmt = select(RoleModel).where(RoleModel.uuid == role_uuid.bytes)
            role_result = await session.execute(role_stmt)
            role_model = role_result.scalar_one_or_none()
            if not role_model:
                raise ValueError("Role not found")

            # Ensure permission exists
            perm_stmt = select(PermissionModel).where(
                PermissionModel.id == permission_id
            )
            perm_result = await session.execute(perm_stmt)
            if not perm_result.scalar_one_or_none():
                raise ValueError("Permission not found")

            session.add(
                RolePermission(role_uuid=role_uuid.bytes, permission_id=permission_id)
            )

    async def remove_permission_from_role(
        self, role_uuid: UUID, permission_id: str
    ) -> None:
        async with self.session() as session:
            await session.execute(
                delete(RolePermission)
                .where(RolePermission.role_uuid == role_uuid.bytes)
                .where(RolePermission.permission_id == permission_id)
            )

    async def get_role_permissions(self, role_uuid: UUID) -> list[Permission]:
        async with self.session() as session:
            stmt = (
                select(PermissionModel)
                .join(
                    RolePermission, PermissionModel.id == RolePermission.permission_id
                )
                .where(RolePermission.role_uuid == role_uuid.bytes)
            )
            result = await session.execute(stmt)
            return [p.as_dataclass() for p in result.scalars().all()]

    async def get_permission_roles(self, permission_id: str) -> list[Role]:
        async with self.session() as session:
            stmt = (
                select(RoleModel)
                .join(RolePermission, RoleModel.uuid == RolePermission.role_uuid)
                .where(RolePermission.permission_id == permission_id)
            )
            result = await session.execute(stmt)
            return [r.as_dataclass() for r in result.scalars().all()]

    async def update_role(self, role: Role) -> None:
        async with self.session() as session:
            # Update role display_name
            await session.execute(
                update(RoleModel)
                .where(RoleModel.uuid == role.uuid.bytes)
                .values(display_name=role.display_name)
            )
            # Sync role permissions: delete all then insert current set
            await session.execute(
                delete(RolePermission).where(
                    RolePermission.role_uuid == role.uuid.bytes
                )
            )
            if role.permissions:
                for perm_id in set(role.permissions):
                    session.add(
                        RolePermission(role_uuid=role.uuid.bytes, permission_id=perm_id)
                    )

    async def delete_role(self, role_uuid: UUID) -> None:
        async with self.session() as session:
            # Prevent deleting a role that still has users
            # Quick existence check for users assigned to the role
            existing_user = await session.execute(
                select(UserModel.uuid).where(UserModel.role_uuid == role_uuid.bytes)
            )
            if existing_user.first() is not None:
                raise ValueError("Cannot delete role with assigned users")

            await session.execute(
                delete(RoleModel).where(RoleModel.uuid == role_uuid.bytes)
            )

    async def get_role(self, role_uuid: UUID) -> Role:
        async with self.session() as session:
            result = await session.execute(
                select(RoleModel).where(RoleModel.uuid == role_uuid.bytes)
            )
            role_model = result.scalar_one_or_none()
            if not role_model:
                raise ValueError("Role not found")
            r_dc = role_model.as_dataclass()
            perms_result = await session.execute(
                select(RolePermission.permission_id).where(
                    RolePermission.role_uuid == role_uuid.bytes
                )
            )
            r_dc.permissions = [row[0] for row in perms_result.fetchall()]
            return r_dc

    async def get_roles_by_organization(self, org_id: str) -> list[Role]:
        async with self.session() as session:
            org_uuid = UUID(org_id)
            result = await session.execute(
                select(RoleModel).where(RoleModel.org_uuid == org_uuid.bytes)
            )
            role_models = result.scalars().all()
            roles: list[Role] = []
            for rm in role_models:
                r_dc = rm.as_dataclass()
                perms_result = await session.execute(
                    select(RolePermission.permission_id).where(
                        RolePermission.role_uuid == rm.uuid
                    )
                )
                r_dc.permissions = [row[0] for row in perms_result.fetchall()]
                roles.append(r_dc)
            return roles

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
                organizations.append(org_model.as_dataclass())

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
            # Build a query that joins sessions, users, roles, organizations, and role_permissions
            stmt = (
                select(
                    SessionModel,
                    UserModel,
                    RoleModel,
                    OrgModel,
                    PermissionModel,
                )
                .select_from(SessionModel)
                .join(UserModel, SessionModel.user_uuid == UserModel.uuid)
                .join(RoleModel, UserModel.role_uuid == RoleModel.uuid)
                .join(OrgModel, RoleModel.org_uuid == OrgModel.uuid)
                .outerjoin(RolePermission, RoleModel.uuid == RolePermission.role_uuid)
                .outerjoin(
                    PermissionModel, RolePermission.permission_id == PermissionModel.id
                )
                .where(SessionModel.key == session_key)
            )

            result = await session.execute(stmt)
            rows = result.fetchall()

            if not rows:
                return None

            # Extract the first row to get session and user data
            first_row = rows[0]
            session_model, user_model, role_model, org_model, _ = first_row

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
            user_obj = user_model.as_dataclass()

            # Create organization object (fill permissions later if needed)
            organization = Org(UUID(bytes=org_model.uuid), org_model.display_name)

            # Create role object
            role = Role(
                uuid=UUID(bytes=role_model.uuid),
                org_uuid=UUID(bytes=role_model.org_uuid),
                display_name=role_model.display_name,
            )

            # Collect all unique permissions for the role
            permissions = []
            seen_permission_ids = set()
            for row in rows:
                _, _, _, _, permission_model = row
                if permission_model and permission_model.id not in seen_permission_ids:
                    permissions.append(
                        Permission(
                            id=permission_model.id,
                            display_name=permission_model.display_name,
                        )
                    )
                    seen_permission_ids.add(permission_model.id)

            # Attach permission IDs to role
            role.permissions = list(seen_permission_ids)

            # Load org permission IDs as well
            org_perm_stmt = select(OrgPermission.permission_id).where(
                OrgPermission.org_uuid == org_model.uuid
            )
            org_perm_result = await session.execute(org_perm_stmt)
            organization.permissions = [row[0] for row in org_perm_result.fetchall()]

            return SessionContext(
                session=session_obj,
                user=user_obj,
                org=organization,
                role=role,
                permissions=permissions if permissions else None,
            )
