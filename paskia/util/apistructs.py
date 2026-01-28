"""API response utilities using msgspec for JSON serialization.

msgspec handles UUID and datetime conversion automatically.
API structs inherit from db structs with kw_only=True to add uuid/key fields.
"""

from datetime import UTC, datetime
from uuid import UUID

import msgspec

from paskia.db.structs import Org, Permission, Role, User
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
    def from_db(cls, u: User) -> "ApiUser":
        return cls(uuid=u.uuid, **msgspec.structs.asdict(u))


class ApiOrg(Org, kw_only=True):
    """Org with uuid serialized."""

    uuid: UUID

    @classmethod
    def from_db(cls, o: Org) -> "ApiOrg":
        return cls(uuid=o.uuid, **msgspec.structs.asdict(o))


class ApiRole(Role, kw_only=True):
    """Role with uuid serialized."""

    uuid: UUID

    @classmethod
    def from_db(cls, r: Role) -> "ApiRole":
        return cls(uuid=r.uuid, **msgspec.structs.asdict(r))


class ApiPermission(Permission, kw_only=True):
    """Permission with uuid serialized."""

    uuid: UUID

    @classmethod
    def from_db(cls, p: Permission) -> "ApiPermission":
        return cls(uuid=p.uuid, **msgspec.structs.asdict(p))


class ApiSession(msgspec.Struct):
    """Session for API responses with computed fields."""

    id: str
    credential_uuid: UUID = msgspec.field(name="credential")
    host: str
    ip: str
    user_agent: str
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
    ) -> "ApiSession":
        return cls(
            id=s.key,
            credential_uuid=s.credential_uuid,
            host=s.host,
            ip=s.ip,
            user_agent=useragent.compact_user_agent(s.user_agent),
            last_renewed=s.expiry - expires_delta,
            is_current=s.key == current_key,
            is_current_host=bool(
                normalized_host and s.host and s.host == normalized_host
            ),
        )
