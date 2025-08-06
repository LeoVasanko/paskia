import base64
import hashlib
import secrets

from .passphrase import is_well_formed


def create_token() -> str:
    return secrets.token_urlsafe(12)  # 16 characters Base64


def session_key(token: str) -> bytes:
    if len(token) != 16:
        raise ValueError("Session token must be exactly 16 characters long")
    return b"sess" + base64.urlsafe_b64decode(token)


def reset_key(passphrase: str) -> bytes:
    if not is_well_formed(passphrase):
        raise ValueError(
            "Trying to reset with a session token in place of a passphrase"
            if len(passphrase) == 16
            else "Invalid passphrase format"
        )
    return b"rset" + hashlib.sha512(passphrase.encode()).digest()[:12]
