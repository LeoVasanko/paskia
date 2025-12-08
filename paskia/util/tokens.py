import hashlib
import secrets

import base64url

from paskia.util.passphrase import is_well_formed


def create_token() -> str:
    return secrets.token_urlsafe(12)  # 16 characters Base64


def session_key(token: str) -> bytes:
    if len(token) != 16:
        raise ValueError("Session token must be exactly 16 characters long")
    return b"sess" + base64url.dec(token)


def encode_session_key(key: bytes) -> str:
    """Encode an opaque session key for external representation."""
    return base64url.enc(key)


def decode_session_key(encoded: str) -> bytes:
    """Decode an opaque session key from its public representation."""
    if not encoded:
        raise ValueError("Invalid session identifier")
    try:
        raw = base64url.dec(encoded)
    except Exception as exc:  # pragma: no cover - defensive
        raise ValueError("Invalid session identifier") from exc
    if not raw.startswith(b"sess"):
        raise ValueError("Invalid session identifier")
    return raw


def reset_key(passphrase: str) -> bytes:
    if not is_well_formed(passphrase):
        raise ValueError(
            "Trying to reset with a session token in place of a passphrase"
            if len(passphrase) == 16
            else "Invalid passphrase format"
        )
    return b"rset" + hashlib.sha512(passphrase.encode()).digest()[:12]
