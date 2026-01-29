"""Hatch build hook for building paskia-js and Vue frontend during package build."""

import subprocess
from pathlib import Path
from sys import stderr

from hatchling.builders.hooks.plugin.interface import BuildHookInterface  # type: ignore

# Import utilities from fastapi-vue
exec(Path(__file__).parent.joinpath("fastapi-vue", "util.py").read_text("UTF-8"))  # noqa: S102


def run(cmd, **kwargs):
    """Run a command and display it."""
    display_cmd = [Path(cmd[0]).name, *cmd[1:]]
    stderr.write(f"### {' '.join(display_cmd)}\n")
    subprocess.run(cmd, check=True, **kwargs)


class CustomBuildHook(BuildHookInterface):
    """Build hook that compiles paskia-js and Vue frontend before packaging."""

    def initialize(self, version, build_data):
        super().initialize(version, build_data)
        stderr.write(">>> Building paskia-js library\n")

        install_cmd, build_cmd = find_build_tool()

        try:
            # Install dependencies for paskia-js
            run(install_cmd, cwd="paskia-js")
            stderr.write("\n")
            # Build paskia-js
            run(build_cmd, cwd="paskia-js")
            stderr.write("\n")
        except Exception as e:
            stderr.write(f"Error occurred while building paskia-js: {e}\n")
            raise

        stderr.write(">>> Building the frontend\n")

        try:
            run(install_cmd, cwd="frontend")
            stderr.write("\n")
            run(build_cmd, cwd="frontend")
        except Exception as e:
            stderr.write(f"Error occurred while building frontend: {e}\n")
            raise
