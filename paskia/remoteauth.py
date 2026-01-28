"""
Cross-device (remote) authentication support.

This module manages the flow for authenticating from another device:
1. Device A (requesting) creates a remote auth request and displays QR/link
2. Device B (authenticating) opens the link and authenticates with passkey
3. Device A receives the session via WebSocket notification

Alternative flow (initiated from profile/authenticating device):
1. Device A (requesting) creates request and displays short pairing code
2. Device B (authenticating) enters the pairing code in their profile
3. Device B authenticates, Device A receives the session

The requests are stored in-memory with short expiration (5 minutes).
The link uses the same /{token} endpoint as reset tokens, but the server
distinguishes between them by checking if the token exists in remoteauth first.
The first 3 words of the token serve as the pairing code for manual entry.
"""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from paskia.util import passphrase, pow

# Remote auth requests expire after this duration
REMOTE_AUTH_LIFETIME = timedelta(minutes=5)


@dataclass
class RemoteAuthRequest:
    """A pending remote authentication request."""

    key: str  # The 3-word passphrase code
    created_at: datetime
    host: str  # The host where the session should be created
    ip: str  # IP of the requesting device
    user_agent: str  # User agent of the requesting device
    action: str = "login"  # "login" or "register"
    locked: bool = False  # True once the authenticating device has entered the code
    # Callback to notify the requesting device when auth completes
    # Takes (session_token, user_uuid, credential_uuid, reset_token) or (None, None, None, None) on cancel/expire
    notify: (
        Callable[[str | None, UUID | None, UUID | None, str | None], None] | None
    ) = None
    # Callback to notify the requesting device when action is locked
    # Takes (action) to confirm what action was locked
    action_locked_notify: Callable[[str], None] | None = None
    # Set when authentication completes
    completed: bool = False
    denied: bool = False  # True if explicitly denied by the authenticating device
    session_token: str | None = None
    user_uuid: UUID | None = None
    credential_uuid: UUID | None = None
    reset_token: str | None = None


class RemoteAuthManager:
    """Manages pending remote authentication requests."""

    def __init__(self):
        self._requests: dict[str, RemoteAuthRequest] = {}  # keyed by 3-word code
        self._cleanup_task: asyncio.Task | None = None
        self._lock = asyncio.Lock()

    async def start(self):
        """Start the cleanup background task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

    async def stop(self):
        """Stop the cleanup background task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def _cleanup_loop(self):
        """Periodically clean up expired requests."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception:
                logging.exception("Error in remote auth cleanup loop")

    async def _cleanup_expired(self):
        """Remove expired requests and notify waiting clients."""
        now = datetime.now(UTC)
        expired_keys = []
        async with self._lock:
            for key, req in self._requests.items():
                if now > req.created_at + REMOTE_AUTH_LIFETIME:
                    expired_keys.append(key)
            for key in expired_keys:
                req = self._requests.pop(key)
                if req.notify and not req.completed:
                    try:
                        req.notify(None, None, None, None)
                    except Exception:
                        pass

    async def create_request(
        self,
        host: str,
        ip: str,
        user_agent: str,
        action: str = "login",
    ) -> tuple[str, datetime]:
        """Create a new remote auth request.

        The code is a 3-word passphrase.
        We ensure uniqueness across concurrent requests.

        Returns:
            (code, expiry) - The 3-word passphrase code and expiration time
        """
        now = datetime.now(UTC)
        expiry = now + REMOTE_AUTH_LIFETIME

        async with self._lock:
            # Generate unique 3-word code
            max_attempts = 100
            for _ in range(max_attempts):
                code = passphrase.generate(n=passphrase.N_WORDS_SHORT)
                if code not in self._requests:
                    break
            else:
                # Extremely unlikely but handle gracefully
                raise ValueError("Unable to generate unique code")

            request = RemoteAuthRequest(
                key=code,
                created_at=now,
                host=host,
                ip=ip,
                user_agent=user_agent,
                action=action,
            )

            self._requests[code] = request

        return code, expiry

    async def get_request(self, code: str) -> RemoteAuthRequest | None:
        """Get a pending request by code, if valid and not expired."""
        # Normalize: lowercase, dot-separated words
        normalized = code.lower().strip().replace(" ", ".")
        if not passphrase.is_well_formed(normalized, n=passphrase.N_WORDS_SHORT):
            return None
        async with self._lock:
            req = self._requests.get(normalized)
            if req is None:
                return None
            now = datetime.now(UTC)
            if now > req.created_at + REMOTE_AUTH_LIFETIME:
                # Expired
                del self._requests[normalized]
                return None
            return req

    async def set_notify_callback(
        self,
        token: str,
        callback: Callable[[str | None, UUID | None, UUID | None, str | None], None],
    ) -> bool:
        """Set the notification callback for a request.

        Returns True if the request exists and callback was set.
        """
        async with self._lock:
            req = self._requests.get(token)
            if req is None:
                return False
            req.notify = callback
            return True

    async def set_action_locked_callback(
        self,
        token: str,
        callback: Callable[[str], None],
    ) -> bool:
        """Set the callback for when the action is locked.

        Returns True if the request exists and callback was set.
        """
        async with self._lock:
            req = self._requests.get(token)
            if req is None:
                return False
            req.action_locked_notify = callback
            return True

    async def update_action(
        self,
        token: str,
        action: str,
    ) -> bool:
        """Update the action for a request (only if not locked).

        Returns True if the request exists and was updated.
        """
        if action not in ("login", "register"):
            return False
        async with self._lock:
            req = self._requests.get(token)
            if req is None or req.locked:
                return False
            req.action = action
            return True

    async def lock_action(
        self,
        token: str,
    ) -> str | None:
        """Lock the action for a request (called when authenticating device enters code).

        Returns the locked action, or None if request doesn't exist or is already locked.
        Notifies the requesting device via action_locked_notify callback.
        """
        async with self._lock:
            req = self._requests.get(token)
            if req is None:
                return None
            if req.locked:
                # Already locked by another authenticating device
                return None
            req.locked = True
            action = req.action
            if req.action_locked_notify:
                try:
                    req.action_locked_notify(action)
                except Exception:
                    pass
            return action

    async def complete_request(
        self,
        token: str,
        session_token: str | None,
        user_uuid: UUID,
        credential_uuid: UUID,
        reset_token: str | None = None,
    ) -> bool:
        """Mark a request as completed with the authentication result.

        The request is removed after notifying the waiting client.
        Returns True if the request existed and was completed.
        """
        async with self._lock:
            req = self._requests.pop(token, None)
            if req is None:
                return False
            if req.notify:
                try:
                    req.notify(session_token, user_uuid, credential_uuid, reset_token)
                except Exception:
                    pass
            return True

    async def cancel_request(
        self, token: str, *, denied: bool = False
    ) -> RemoteAuthRequest | None:
        """Cancel and remove a request.

        Args:
            token: The request token
            denied: If True, marks this as an explicit denial (not just timeout/disconnect)

        Returns the removed request if it existed, None otherwise.
        """
        async with self._lock:
            req = self._requests.pop(token, None)
            if req is None:
                return None
            if denied:
                req.denied = True
            if req.notify and not req.completed:
                try:
                    # Pass denied status through a special UUID value (all zeros means denied)
                    if denied:
                        req.notify(None, UUID(int=0), None, None)
                    else:
                        req.notify(None, None, None, None)
                except Exception:
                    pass
            return req

    def get_connection_count(self) -> int:
        """Get the current count of open WebSocket connections.

        This is used to determine PoW difficulty based on load.
        """
        # Count is maintained externally by the WebSocket endpoints
        return getattr(self, "_ws_count", 0)

    def increment_connections(self) -> None:
        """Increment the WebSocket connection counter."""
        self._ws_count = getattr(self, "_ws_count", 0) + 1

    def decrement_connections(self) -> None:
        """Decrement the WebSocket connection counter."""
        self._ws_count = max(0, getattr(self, "_ws_count", 0) - 1)

    def get_pow_difficulty(self) -> int:
        """Get PoW difficulty based on current WebSocket connection count.

        Uses NORMAL difficulty with low load (< 10 connections),
        HARD difficulty with high load (>= 10 connections).

        Returns:
            PoW work units (pow.NORMAL or pow.HARD)
        """

        count = self.get_connection_count()
        return pow.HARD if count >= 10 else pow.NORMAL

    async def consume_request(self, token: str) -> RemoteAuthRequest | None:
        """Get and remove a request (for use by the authenticating device)."""
        if not passphrase.is_well_formed(token, n=passphrase.N_WORDS_SHORT):
            return None
        async with self._lock:
            req = self._requests.get(token)
            if req is None:
                return None
            now = datetime.now(UTC)
            if now > req.created_at + REMOTE_AUTH_LIFETIME:
                del self._requests[token]
                return None
            # Don't remove yet - wait until completion
            return req


# Global instance
instance: RemoteAuthManager | None = None


async def init():
    """Initialize the global remote auth manager."""
    global instance
    instance = RemoteAuthManager()
    await instance.start()


async def shutdown():
    """Shutdown the global remote auth manager."""
    global instance
    if instance:
        await instance.stop()
        instance = None
