import shutil
import subprocess
from pathlib import Path
from sys import stderr

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def run(cmd, **kwargs):
    display_cmd = [Path(cmd[0]).name, *cmd[1:]]
    stderr.write(f"### {' '.join(display_cmd)}\n")
    subprocess.run(cmd, check=True, **kwargs)


def find_build_tool():
    install = [
        ("deno", "install", "--allow-scripts=npm:vue-demi"),
        ("npm", "install"),
        ("bun", "--bun", "install"),
    ]

    build = [
        ("deno", "task", "build"),
        ("npm", "run", "build"),
        ("bun", "--bun", "run", "build"),
    ]

    for i, b in zip(install, build, strict=False):
        if tool := shutil.which(i[0]):
            return [tool, *i[1:]], [tool, *b[1:]]

    raise RuntimeError("Deno, npm or Bun is required for building but none was found")


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        super().initialize(version, build_data)
        stderr.write(">>> Building the frontend\n")

        install_cmd, build_cmd = find_build_tool()

        try:
            run(install_cmd, cwd="frontend")
            stderr.write("\n")
            run(build_cmd, cwd="frontend")
        except Exception as e:
            stderr.write(f"Error occurred while building frontend: {e}\n")
            raise
