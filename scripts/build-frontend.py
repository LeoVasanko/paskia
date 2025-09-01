import os
import shutil
import subprocess
from contextlib import contextmanager
from sys import stderr

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


@contextmanager
def chdir(path):
    original = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(original)


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        super().initialize(version, build_data)
        stderr.write(">>> Building the frontend\n")
        npm = None
        bun = shutil.which("bun")
        if bun is None:
            npm = shutil.which("npm")
            if npm is None:
                raise RuntimeError(
                    "Bun or NodeJS `npm` is required for building but neither was found"
                )
        # npm --prefix doesn't work on Windows, so we chdir instead
        with chdir("frontend"):
            try:
                if npm:
                    stderr.write("### npm install\n")
                    subprocess.run([npm, "install"], check=True)  # noqa: S603
                    stderr.write("\n### npm run build\n")
                    subprocess.run([npm, "run", "build"], check=True)  # noqa: S603
                else:
                    assert bun
                    stderr.write("### bun --bun install\n")
                    subprocess.run([bun, "--bun", "install"], check=True)  # noqa: S603
                    stderr.write("\n### bun --bun run build\n")
                    subprocess.run([bun, "--bun", "run", "build"], check=True)  # noqa: S603
            except Exception:
                stderr.write("Error occurred while building frontend\n")
