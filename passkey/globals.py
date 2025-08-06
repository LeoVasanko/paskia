from typing import Generic, TypeVar

from .db import DatabaseInterface
from .sansio import Passkey

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
    rp_id: str = "localhost", rp_name: str | None = None, origin: str | None = None
) -> None:
    """Initialize the global database, passkey instance, and bootstrap the system if needed."""
    # Initialize passkey instance with provided parameters
    passkey.instance = Passkey(
        rp_id=rp_id,
        rp_name=rp_name or rp_id,
        origin=origin,
    )

    # Test if we have a database already initialized, otherwise use SQL
    try:
        db.instance
    except RuntimeError:
        from .db import sql

        await sql.init()

    # Bootstrap system if needed
    from .bootstrap import bootstrap_if_needed

    await bootstrap_if_needed()


# Global instances
passkey = Manager[Passkey]("Passkey")
db = Manager[DatabaseInterface]("Database")
