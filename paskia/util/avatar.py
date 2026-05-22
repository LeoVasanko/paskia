"""Avatar storage and URL helpers."""

from __future__ import annotations

import contextlib
import hashlib
from pathlib import Path
from uuid import UUID

from fastapi import HTTPException, UploadFile

from paskia.db.paths import users_root_path
from paskia.util import hostutil

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def media_root() -> Path:
    """Return the filesystem root for auxiliary media files."""
    return users_root_path(create_root=True)


def avatars_root() -> Path:
    """Return the filesystem root for stored avatar images."""
    return media_root()


def avatar_path(user_uuid: UUID) -> Path:
    """Return the avatar file path for a user."""
    return avatars_root() / str(user_uuid) / "profile.webp"


def avatar_public_path(user_uuid: UUID) -> str:
    """Return the public relative path for a user's avatar."""
    return f"/auth/api/user/{user_uuid}/profile.webp"


def avatar_browser_url(user_uuid: UUID) -> str | None:
    """Return the browser-facing avatar URL."""
    if not avatar_path(user_uuid).is_file():
        return None
    return avatar_public_path(user_uuid)


def avatar_url(user_uuid: UUID) -> str | None:
    """Return the absolute public avatar URL for a user, or None."""
    if not avatar_path(user_uuid).is_file():
        return None
    return f"{hostutil.auth_site_url()}api/user/{user_uuid}/profile.webp"


def current_avatar_url(user_uuid: UUID) -> str | None:
    """Return the current absolute avatar URL for a user UUID."""
    return avatar_url(user_uuid)


def remove_avatar_file(user_uuid: UUID) -> None:
    """Delete a stored avatar file if it exists."""
    with contextlib.suppress(FileNotFoundError):
        avatar_path(user_uuid).unlink()


def read_avatar_bytes(user_uuid: UUID) -> bytes | None:
    """Read the stored avatar file for a user, if present."""
    path = avatar_path(user_uuid)
    if not path.is_file():
        return None
    return path.read_bytes()


def _is_webp(data: bytes) -> bool:
    """Return True when bytes look like a RIFF WebP file."""
    return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"


async def read_upload(upload: UploadFile) -> bytes:
    """Read an uploaded avatar and require it to already be WebP."""
    data = await upload.read(MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(status_code=400, detail="No avatar file uploaded")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Avatar upload too large")

    if not _is_webp(data):
        raise HTTPException(status_code=400, detail="Avatar upload must be WebP")

    return data


def store_avatar(user_uuid: UUID, data: bytes) -> None:
    """Store avatar bytes."""
    path = avatar_path(user_uuid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def avatar_etag(data: bytes) -> str:
    """Return a stable ETag value for avatar bytes."""
    return hashlib.sha256(data).hexdigest()[:16]
