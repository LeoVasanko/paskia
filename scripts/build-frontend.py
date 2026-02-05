"""Hatch build hook for building paskia-js and Vue frontend during package build."""

import sys
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # type: ignore

sys.path.insert(0, str(Path(__file__).parent / "fastapi-vue"))
from buildutil import build  # noqa: E402


class CustomBuildHook(BuildHookInterface):
    """Build hook that compiles paskia-js and Vue frontend before packaging."""

    def initialize(self, version, build_data):
        super().initialize(version, build_data)
        build("paskia-js")
        build("frontend")
