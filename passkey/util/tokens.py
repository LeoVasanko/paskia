import base64
import hashlib
import secrets


def create_token() -> str:
    return secrets.token_urlsafe(12)  # 16 characters Base64


def session_key(token: str) -> bytes:
    if len(token) != 16:
        raise ValueError("Session token must be exactly 16 characters long")
    return b"sess" + base64.urlsafe_b64decode(token)


def reset_key(passphrase: str) -> bytes:
    return b"rset" + hashlib.sha512(passphrase.encode()).digest()[:12]
