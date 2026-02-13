from __future__ import annotations

"""API response utilities using msgspec for JSON serialization.

msgspec handles UUID and datetime conversion automatically.
API structs inherit from db structs with kw_only=True to add uuid/key fields.
"""

from datetime import UTC, datetime
from uuid import UUID

import msgspec

from paskia.db.structs import Credential, Org, Permission, Role, User
from paskia.util import useragent


def _utc_datetime(dt: datetime | None) -> datetime | None:
    """Convert datetime to UTC, handling both aware and naive datetimes."""
    if dt is None:
        return None
    if dt.tzinfo:
        return dt.astimezone(UTC)
    return dt.replace(tzinfo=UTC)


def format_datetime(dt: datetime | None) -> str | None:
    """Format a datetime to ISO 8601 string with Z suffix for UTC."""
    if dt is None:
        return None
    utc_dt = _utc_datetime(dt)
    return utc_dt.isoformat().replace("+00:00", "Z") if utc_dt else None


# -------------------------------------------------------------------------
# API structs - inherit from db structs, add uuid for serialization
# -------------------------------------------------------------------------


class ApiUser(User, kw_only=True):
    """User with uuid serialized."""

    uuid: UUID

    @classmethod
    def from_db(cls, u: User) -> ApiUser:
        return cls(uuid=u.uuid, **msgspec.structs.asdict(u))


class ApiOrg(Org, kw_only=True):
    """Org with uuid serialized."""

    uuid: UUID

    @classmethod
    def from_db(cls, o: Org) -> ApiOrg:
        return cls(uuid=o.uuid, **msgspec.structs.asdict(o))


class ApiRole(Role, kw_only=True):
    """Role with uuid serialized."""

    uuid: UUID

    @classmethod
    def from_db(cls, r: Role) -> ApiRole:
        return cls(uuid=r.uuid, **msgspec.structs.asdict(r))


class ApiPermission(msgspec.Struct, kw_only=True):
    """Permission for API responses, without org details."""

    scope: str
    display_name: str
    domain: str | None = None

    @classmethod
    def from_db(cls, p: Permission) -> ApiPermission:
        return cls(
            scope=p.scope,
            display_name=p.display_name,
            domain=p.domain,
        )


class ApiAaguidInfo(msgspec.Struct, kw_only=True, omit_defaults=True):
    """AAGUID information for authenticators."""

    name: str
    icon: str | None = None
    icon_dark: str | None = None


class ApiUserSession(msgspec.Struct):
    """Session for user info responses with computed fields."""

    credential_uuid: UUID = msgspec.field(name="credential")
    host: str
    ip: str
    user_agent: str
    expiry: datetime
    last_renewed: datetime
    is_current: bool = False
    is_current_host: bool = False

    @classmethod
    def from_db(
        cls,
        s,  # Session
        *,
        current_key: str,
        normalized_host: str | None,
        expires_delta,  # timedelta
    ) -> ApiUserSession:
        return cls(
            credential_uuid=s.credential_uuid,
            host=s.host,
            ip=s.ip,
            user_agent=useragent.compact_user_agent(s.user_agent),
            expiry=s.expiry,
            last_renewed=s.expiry - expires_delta,
            is_current=s.key == current_key,
            is_current_host=bool(
                normalized_host and s.host and s.host == normalized_host
            ),
        )


class ApiUserDetail(msgspec.Struct, kw_only=True):
    """User detail response with credentials and sessions."""

    user: ApiUser
    credentials: dict[UUID, Credential]
    aaguid_info: dict[str, ApiAaguidInfo]
    sessions: list[ApiUserSession]
    permissions: dict[UUID, ApiPermission] = {}


# -------------------------------------------------------------------------
# Nested API structs for org response - without uuid
# -------------------------------------------------------------------------


class ApiOrgResponse(msgspec.Struct, kw_only=True):
    """Org response containing Org with roles and users as UUID-keyed dicts."""

    org: Org
    permissions: dict[UUID, Permission]
    roles: dict[UUID, Role]
    users: dict[UUID, User]


class ApiSettings(msgspec.Struct):
    """Settings response struct."""

    rp_id: str
    rp_name: str
    ui_base_path: str
    auth_host: str | None
    auth_site_url: str
    session_cookie: str
    version: str


class ApiTokenInfo(msgspec.Struct):
    """Token info response struct."""

    token_type: str
    display_name: str


class ApiUuidResponse(msgspec.Struct):
    """Response struct for creation endpoints returning a UUID."""

    uuid: str


class ApiCreateLinkResponse(msgspec.Struct):
    """Response struct for create-link endpoints."""

    url: str
    expires: str
    token_type: str
    message: str | None = None


class ApiUserContext(msgspec.Struct, omit_defaults=True):
    """User context for session validation."""

    uuid: str
    display_name: str
    theme: str = ""


class ApiOrgContext(msgspec.Struct):
    """Org context for session validation."""

    uuid: str
    display_name: str


class ApiRoleContext(msgspec.Struct):
    """Role context for session validation."""

    uuid: str
    display_name: str


class ApiSessionContext(msgspec.Struct):
    """Session context struct."""

    user: ApiUserContext
    org: ApiOrgContext
    role: ApiRoleContext
    permissions: list[str]


class ApiValidateResponse(msgspec.Struct):
    """Response struct for validate endpoint."""

    valid: bool
    renewed: bool
    ctx: ApiSessionContext
