import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def hash_secret(*data) -> bytes:
    """A custom HMAC that securily combines and hashes the given data (context, secrets). The first argument should be a namespacing string."""
    inner = bytearray(len(data).to_bytes(8, "big"))
    for d in data:
        if isinstance(d, str):
            d = d.encode()
        inner += hashlib.sha256(d).digest()
    return hashlib.sha256(inner).digest()[:12]


def secret_key() -> bytes:
    """Generate a new Ed25519 private key and return as 32 raw bytes."""
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_from_secret(secret_key_bytes: bytes) -> Ed25519PrivateKey:
    """Load Ed25519 private key from 32 raw bytes."""
    return Ed25519PrivateKey.from_private_bytes(secret_key_bytes)


def get_public_key_der(private_key: Ed25519PrivateKey) -> bytes:
    """Get DER-encoded public key for kid generation."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def generate_kid(public_key_der: bytes) -> str:
    """Generate key ID from public key DER bytes."""
    return hashlib.sha256(public_key_der).hexdigest()[:16]


def get_public_key_raw(private_key: Ed25519PrivateKey) -> bytes:
    """Get raw 32-byte public key for JWKS."""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
