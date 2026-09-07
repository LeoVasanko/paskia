"""
OIDC JWT utilities for signing ID tokens and serving JWKS.

The OIDC provider is instance-global: a single signing key serves all
domains, with each request Host acting as an issuer alias.
"""

import hashlib
from base64 import urlsafe_b64encode
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt

from paskia import db
from paskia.util.crypto import (
    generate_kid,
    get_public_key_der,
    get_public_key_raw,
    public_key_from_secret,
    secret_key,
)

# JWT signing key (loaded on first use): (private, public, kid)
_key: tuple[object, object, str] | None = None


def _load_or_generate_key() -> tuple[object, object, str]:
    """Load the Ed25519 signing key or generate and store a new one."""
    data = db.data()
    provider = data.oidc
    store = data._store
    if store is None:
        raise RuntimeError("Kanta store is not initialized")
    if provider.key is not None:
        private_key = public_key_from_secret(provider.key)
    else:
        raw_key = secret_key()
        with store.transaction("oidc_key"):
            provider.key = raw_key
        private_key = public_key_from_secret(raw_key)

    public_key = private_key.public_key()
    # Generate kid from public key fingerprint
    kid = generate_kid(get_public_key_der(private_key))
    return private_key, public_key, kid


def _ensure_key() -> tuple[object, object, str]:
    """Ensure the signing key is loaded and return (private, public, kid)."""
    global _key
    if _key is None:
        _key = _load_or_generate_key()
    return _key


def get_jwks() -> dict:
    """Get JWKS (JSON Web Key Set) for public key verification."""
    private_key, _, kid = _ensure_key()
    # Ed25519 public key is 32 bytes raw
    pub_bytes = get_public_key_raw(private_key)
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": kid,
                "x": urlsafe_b64encode(pub_bytes).rstrip(b"=").decode("ascii"),
            }
        ]
    }


def create_id_token(
    issuer: str,
    subject: UUID,
    audience: str,  # client_id
    nonce: str | None = None,
    sid: str | None = None,
    name: str | None = None,
    preferred_username: str | None = None,
    email: str | None = None,
    picture: str | None = None,
    groups: list[str] | None = None,
    auth_time: datetime | None = None,
    expires_in: int = 3600,
) -> str:
    """Create a signed ID token (JWT).

    Args:
        issuer: Token issuer (site URL)
        subject: User UUID (sub claim)
        audience: Client ID (aud claim)
        nonce: Nonce from authorization request
        sid: Session ID for backchannel logout
        name: User's display name
        preferred_username: User's preferred username
        email: User's email address
        picture: User avatar URL
        groups: List of permission scopes (groups claim)
        auth_time: When the user authenticated (last credential use time)
        expires_in: Token lifetime in seconds

    Returns:
        Signed JWT string
    """
    private_key, _, kid = _ensure_key()
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "iss": issuer,
        "sub": str(subject),
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    if nonce:
        payload["nonce"] = nonce
    if sid:
        payload["sid"] = sid
    if name:
        payload["name"] = name
    if preferred_username:
        payload["preferred_username"] = preferred_username
    if email:
        payload["email"] = email
    if picture:
        payload["picture"] = picture
    if groups:
        payload["groups"] = groups
    if auth_time:
        payload["auth_time"] = int(auth_time.timestamp())

    return jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


def create_access_token(
    issuer: str,
    subject: UUID,
    audience: str,
    scope: str,
    expires_in: int = 3600,
) -> str:
    """Create a signed access token (JWT) for userinfo endpoint.

    Args:
        issuer: Token issuer (site URL)
        subject: User UUID
        audience: Client ID
        scope: Granted scopes
        expires_in: Token lifetime in seconds

    Returns:
        Signed JWT string
    """
    private_key, _, kid = _ensure_key()
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "iss": issuer,
        "sub": str(subject),
        "aud": audience,
        "scope": scope,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    return jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})


def decode_access_token(
    token: str, issuer: str, audience: str | None = None
) -> dict | None:
    """Decode and verify an access token.

    Args:
        token: JWT string
        issuer: Expected issuer
        audience: Optional expected audience (client_id). If provided, aud claim must match.

    Returns:
        Decoded payload or None if invalid
    """
    _, public_key, _ = _ensure_key()
    try:
        if audience is not None:
            return jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                issuer=issuer,
                audience=audience,
            )

        return jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            issuer=issuer,
            options={"verify_aud": False},
        )
    except jwt.PyJWTError:
        return None


def create_logout_token(
    issuer: str,
    audience: str,
    sid: str | None = None,
    sub: UUID | None = None,
) -> str:
    """Create a signed logout token for back-channel logout notification.

    Per OIDC Back-Channel Logout 1.0, the logout token must contain
    either sid (session) or sub (user), or both.

    Args:
        issuer: Token issuer (site URL)
        audience: Client ID (aud claim)
        sid: Session ID (base64url-encoded)
        sub: User UUID

    Returns:
        Signed JWT string
    """
    private_key, _, kid = _ensure_key()
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=120)).timestamp()),
        "events": {"http://schemas.openid.net/event/backchannel-logout": {}},
        "jti": hashlib.sha256(
            f"{now.timestamp()}{audience}{sid}{sub}".encode()
        ).hexdigest()[:16],
    }
    if sid:
        payload["sid"] = sid
    if sub:
        payload["sub"] = str(sub)
    return jwt.encode(payload, private_key, algorithm="EdDSA", headers={"kid": kid})
