from pathlib import Path

from fastapi_vue import Frontend

# Vue Frontend static files
frontend = Frontend(
    Path(__file__).parent.parent / "frontend-build",
    cached=["/auth/assets/"],
    favicon="/paskia.webp",
)
