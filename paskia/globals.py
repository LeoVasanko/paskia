from typing import Generic, TypeVar

from paskia import db, remoteauth
from paskia.bootstrap import bootstrap_if_needed
from paskia.db import start_background
from paskia.sansio import Passkey

T = TypeVar("T")


class Manager(Generic[T]):
    """Generic manager for global instances."""

    def __init__(self, name: str):
        self._instance: T | None = None
        self._name = name

    @property
    def instance(self) -> T:
        if self._instance is None:
            raise RuntimeError(
                f"{self._name} not initialized. Call globals.init() first."
            )
        return self._instance

    @instance.setter
    def instance(self, instance: T) -> None:
        self._instance = instance


async def init(
    rp_id: str = "localhost",
    rp_name: str | None = None,
    origins: list[str] | None = None,
    *,
    bootstrap: bool = True,
) -> None:
    """Initialize global passkey + database.

    If bootstrap=True (default) the system bootstrap_if_needed() will be invoked.
    In FastAPI lifespan we call with bootstrap=False to avoid duplicate bootstrapping
    since the CLI performs it once before servers start.

    Database configuration:
        Set PASKIA_DB environment variable to specify the JSONL database file path.
        Default: paskia.jsonl
    """

    # Initialize passkey instance with provided parameters
    passkey.instance = Passkey(
        rp_id=rp_id,
        rp_name=rp_name or rp_id,
        origins=origins,
    )

    # Initialize database
    await db.init()

    # Initialize remote auth manager
    await remoteauth.init()

    if bootstrap:
        # Bootstrap system if needed

        await bootstrap_if_needed()

    # Start background flush/cleanup task after bootstrap

    await start_background()


# Global instances
passkey = Manager[Passkey]("Passkey")
