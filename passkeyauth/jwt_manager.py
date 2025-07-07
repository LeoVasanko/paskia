"""
JWT session management for WebAuthn authentication.

This module provides JWT token generation and validation for managing user sessions
after successful WebAuthn authentication. Tokens contain user ID and credential ID
for session validation.
"""

import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from uuid import UUID

import jwt

SECRET_FILE = Path("server-secret.bin")


def load_or_create_secret() -> bytes:
    """Load JWT secret from file or create a new one."""
    if SECRET_FILE.exists():
        return SECRET_FILE.read_bytes()
    else:
        # Generate a new 32-byte secret
        secret = secrets.token_bytes(32)
        SECRET_FILE.write_bytes(secret)
        return secret


class JWTManager:
    """Manages JWT tokens for user sessions."""

    def __init__(self, secret_key: bytes, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.token_expiry = timedelta(hours=24)  # Tokens expire after 24 hours

    def create_token(self, user_id: UUID, credential_id: bytes) -> str:
        """
        Create a JWT token for a user session.

        Args:
            user_id: The user's UUID
            credential_id: The credential ID used for authentication

        Returns:
            JWT token string
        """
        now = datetime.utcnow()
        payload = {
            "user_id": str(user_id),
            "credential_id": credential_id.hex(),
            "iat": now,
            "exp": now + self.token_expiry,
            "iss": "passkeyauth",
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def validate_token(self, token: str) -> Optional[dict]:
        """
        Validate a JWT token and return the payload.

        Args:
            token: JWT token string

        Returns:
            Dictionary with user_id and credential_id, or None if invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer="passkeyauth",
            )

            return {
                "user_id": UUID(payload["user_id"]),
                "credential_id": bytes.fromhex(payload["credential_id"]),
                "issued_at": payload["iat"],
                "expires_at": payload["exp"],
            }
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def refresh_token(self, token: str) -> Optional[str]:
        """
        Refresh a JWT token if it's still valid.

        Args:
            token: Current JWT token

        Returns:
            New JWT token string, or None if the current token is invalid
        """
        payload = self.validate_token(token)
        if payload is None:
            return None

        return self.create_token(payload["user_id"], payload["credential_id"])


# Global JWT manager instance
_jwt_manager: Optional[JWTManager] = None


def get_jwt_manager() -> JWTManager:
    """Get the global JWT manager instance."""
    global _jwt_manager
    if _jwt_manager is None:
        secret = load_or_create_secret()
        _jwt_manager = JWTManager(secret)
    return _jwt_manager


def create_session_token(user_id: UUID, credential_id: bytes) -> str:
    """Create a session token for a user."""
    return get_jwt_manager().create_token(user_id, credential_id)


def validate_session_token(token: str) -> Optional[dict]:
    """Validate a session token."""
    return get_jwt_manager().validate_token(token)


def refresh_session_token(token: str) -> Optional[str]:
    """Refresh a session token."""
    return get_jwt_manager().refresh_token(token)
