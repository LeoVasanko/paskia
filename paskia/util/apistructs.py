"""API response utilities using msgspec for JSON serialization.

msgspec handles UUID and datetime conversion automatically.
API structs inherit from db structs with kw_only=True to add uuid/key fields.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

import msgspec

from paskia import db
from paskia.db.structs import Credential, Org, Permission, Role, User
from paskia.util import useragent

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


class ApiOidcClient(msgspec.Struct, kw_only=True):
    """OIDC Client for API responses."""

    name: str
    redirect_uris: list[str]
    backchannel_logout_uri: str | None = None
    active_sessions: int = 0

    @classmethod
    def from_db(cls, c, active_sessions: int = 0):
        return cls(
            name=c.name,
            redirect_uris=c.redirect_uris,
            backchannel_logout_uri=c.backchannel_logout_uri,
            active_sessions=active_sessions,
        )


class ApiAaguidInfo(msgspec.Struct, kw_only=True, omit_defaults=True):
    """AAGUID information for authenticators."""

    name: str
    icon: str | None = None
    icon_dark: str | None = None


class ApiUserSession(msgspec.Struct, omit_defaults=True):
    """Session for user info responses with computed fields."""

    credential_uuid: UUID = msgspec.field(name="credential")
    host: str
    ip: str
    user_agent: str
    validated: datetime
    last_renewed: datetime
    is_current: bool = False
    is_current_host: bool = False
    client_uuid: UUID | None = msgspec.field(name="client", default=None)
    client_name: str | None = None

    @classmethod
    def from_db(
        cls,
        s,  # Session
        *,
        current_key: str,
        normalized_host: str | None,
    ) -> ApiUserSession:
        client_name = None
        if s.client_uuid:
            c = db.data().oidc.clients.get(s.client_uuid)
            client_name = c.name if c else str(s.client_uuid)
        return cls(
            credential_uuid=s.credential_uuid,
            host=s.host,
            ip=s.ip,
            user_agent=useragent.compact_user_agent(s.user_agent),
            validated=s.validated,
            last_renewed=s.validated,
            is_current=s.key == current_key,
            is_current_host=not s.client_uuid
            and bool(normalized_host and s.host and s.host == normalized_host),
            client_uuid=s.client_uuid,
            client_name=client_name,
        )


class ApiUserDetail(msgspec.Struct, kw_only=True):
    """User detail response with credentials and sessions."""

    user: ApiUser
    credentials: dict[UUID, Credential]
    aaguid_info: dict[str, ApiAaguidInfo]
    sessions: dict[bytes, ApiUserSession]
    permissions: dict[UUID, ApiPermission] = {}
    org: ApiOrg | None = None
    role: ApiRole | None = None


# -------------------------------------------------------------------------
# Nested API structs for org response - without uuid
# -------------------------------------------------------------------------


class ApiOrgResponse(msgspec.Struct, kw_only=True):
    """Org response containing Org with roles and users as UUID-keyed dicts."""

    org: ApiOrg
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
    expires: datetime
    token_type: str
    message: str | None = None


class ApiUserContext(msgspec.Struct, omit_defaults=True):
    """User context for session validation."""

    uuid: UUID
    display_name: str
    theme: str = ""


class ApiOrgContext(msgspec.Struct):
    """Org context for session validation."""

    uuid: UUID
    display_name: str


class ApiRoleContext(msgspec.Struct):
    """Role context for session validation."""

    uuid: UUID
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


class ApiAdminInfo(msgspec.Struct, kw_only=True):
    """Combined admin info response."""

    orgs: dict[UUID, ApiOrgResponse]
    permissions: dict[UUID, ApiPermission]
    oidc_clients: dict[UUID, ApiOidcClient] = {}
