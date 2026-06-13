"""Global Passkey instance configured from PASKIA_CONFIG.

The Passkey instance is created at import time using the runtime configuration
passed via the ``PASKIA_CONFIG`` environment variable.  Other runtime setup
(remote auth, auth codes, bootstrap checks) is performed explicitly by the
FastAPI lifespan once the database is open.
"""

from paskia.sansio import Passkey
from paskia.util import runtime

runtime = runtime.config()
if runtime is None:
    raise RuntimeError("PASKIA_CONFIG must be defined before importing paskia.globals")

passkey = Passkey(
    rp_id=runtime.config.rp_id,
    rp_name=runtime.config.rp_name,
    origins=runtime.config.origins,
)
