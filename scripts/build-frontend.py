# noqa: INP001
import os
import shutil
import subprocess
from sys import stderr

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        super().initialize(version, build_data)
        stderr.write(">>> Building Jacloud frontend\n")
        npm = None
        bun = shutil.which("bun")
        if bun is None:
            npm = shutil.which("npm")
            if npm is None:
                raise RuntimeError(
                    "Bun or NodeJS `npm` is required for building but neither was found"
                )
        # npm --prefix doesn't work on Windows, so we chdir instead
        os.chdir("frontend")
        try:
            if npm:
                stderr.write("### npm install\n")
                subprocess.run([npm, "install"], check=True)  # noqa: S603
                stderr.write("\n### npm run build\n")
                subprocess.run([npm, "run", "build"], check=True)  # noqa: S603
            else:
                stderr.write("### bun install\n")
                subprocess.run([bun, "install"], check=True)  # noqa: S603
                stderr.write("\n### bun run build\n")
                subprocess.run([bun, "run", "build"], check=True)  # noqa: S603
        finally:
            os.chdir("..")
