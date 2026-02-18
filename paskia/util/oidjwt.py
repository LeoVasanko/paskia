"""
OIDC JWT utilities for signing ID tokens and serving JWKS.
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

# JWT signing key (loaded on first use)
_private_key = None
_public_key = None
_kid: str | None = None


def _load_or_generate_key() -> None:
    """Load existing Ed25519 key or generate a new one."""
    global _private_key, _public_key, _kid

    data = db.data()
    if data.oidc.key is not None:
        _private_key = public_key_from_secret(data.oidc.key)
    else:
        raw_key = secret_key()
        with data.transaction("oidc_key"):
            data.oidc.key = raw_key
        _private_key = public_key_from_secret(raw_key)

    _public_key = _private_key.public_key()
    # Generate kid from public key fingerprint
    pub_der = get_public_key_der(_private_key)
    _kid = generate_kid(pub_der)


def _ensure_key() -> None:
    """Ensure key is loaded."""
    if _private_key is None:
        _load_or_generate_key()


def get_jwks() -> dict:
    """Get JWKS (JSON Web Key Set) for public key verification."""
    _ensure_key()
    assert _public_key is not None
    # Ed25519 public key is 32 bytes raw
    pub_bytes = get_public_key_raw(_private_key)
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": _kid,
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
        groups: List of permission scopes (groups claim)
        auth_time: When the user authenticated (last credential use time)
        expires_in: Token lifetime in seconds

    Returns:
        Signed JWT string
    """
    _ensure_key()
    now = datetime.now(UTC)
    payload = {
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
    if groups:
        payload["groups"] = groups
    if auth_time:
        payload["auth_time"] = int(auth_time.timestamp())

    return jwt.encode(payload, _private_key, algorithm="EdDSA", headers={"kid": _kid})


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
    _ensure_key()
    now = datetime.now(UTC)
    payload = {
        "iss": issuer,
        "sub": str(subject),
        "aud": audience,
        "scope": scope,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    return jwt.encode(payload, _private_key, algorithm="EdDSA", headers={"kid": _kid})


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
    _ensure_key()
    try:
        # PyJWT requires audience parameter when token has aud claim.
        # When audience is None, we skip PyJWT's audience validation and validate manually.
        options = {}
        decode_kwargs = {
            "algorithms": ["EdDSA"],
            "issuer": issuer,
        }
        if audience is not None:
            decode_kwargs["audience"] = audience
        else:
            options["verify_aud"] = False

        return jwt.decode(token, _public_key, options=options, **decode_kwargs)
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
    _ensure_key()
    now = datetime.now(UTC)
    payload = {
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
    return jwt.encode(payload, _private_key, algorithm="EdDSA", headers={"kid": _kid})
