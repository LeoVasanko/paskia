#!/usr/bin/env -S uv run
"""Release build for paskia (PyPI) and paskia-js (npm).

Usage: release.py [patch|minor|major]  (default: patch)

Bumps the version from the latest vX.Y.Z tag, commits "Release x.y.z" with
the paskia-js version bump and tags it, then builds both packages from a
clean slate. On failure the release commit and tag are rolled back.
Publishing is left to the user; the command is printed on success.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Build outputs removed before building
ARTIFACTS = ["dist", "paskia-js/dist", "paskia/frontend-build", "build"]

# Dependency state removed for a fresh upstream resolve (all untracked)
JS_DIRS = ["paskia-js", "frontend"]
JS_JUNK = ["node_modules", "package-lock.json", "deno.lock", "bun.lock"]

BUMPS = ("patch", "minor", "major")


def run(cmd: list[str], cwd: Path = REPO_ROOT) -> None:
    print(f"### {' '.join(cmd)}")
    subprocess.run(cmd, cwd=cwd, check=True)  # noqa: S603


def abort(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def git(*args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args], cwd=REPO_ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def check_clean_tree() -> None:
    status = git("status", "--porcelain")
    if status:
        print(status, file=sys.stderr)
        abort("working tree is not clean; commit or stash all changes first")


def latest_version() -> tuple[int, int, int]:
    """Highest vX.Y.Z tag, as a tuple."""
    tags = []
    for tag in git("tag", "--list", "v*").splitlines():
        parts = tag.removeprefix("v").split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            tags.append(tuple(int(p) for p in parts))
    if not tags:
        abort("no existing vX.Y.Z tags found")
    return max(tags)


def next_version(bump: str) -> tuple[int, int, int]:
    major, minor, patch = latest_version()
    if bump == "major":
        return (major + 1, 0, 0)
    if bump == "minor":
        return (major, minor + 1, 0)
    return (major, minor, patch + 1)


def set_js_version(version: str) -> None:
    pkg_path = REPO_ROOT / "paskia-js/package.json"
    pkg = json.loads(pkg_path.read_text())
    if pkg.get("version") == version:
        return
    print(f"paskia-js/package.json: {pkg.get('version')} -> {version}")
    pkg["version"] = version
    pkg_path.write_text(json.dumps(pkg, indent=2) + "\n")


def remove(path: Path, rel: str) -> None:
    if not path.exists():
        return
    print(f"rm -rf {rel}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def clean() -> None:
    for rel in ARTIFACTS:
        remove(REPO_ROOT / rel, rel)
    for d in JS_DIRS:
        for junk in JS_JUNK:
            remove(REPO_ROOT / d / junk, f"{d}/{junk}")


def main() -> None:
    bump = sys.argv[1] if len(sys.argv) == 2 else "patch"
    if len(sys.argv) > 2 or bump not in BUMPS:
        print(__doc__)
        raise SystemExit(1)

    check_clean_tree()
    version_tuple = next_version(bump)
    version = ".".join(str(p) for p in version_tuple)
    tag = f"v{version}"
    if tag in git("tag", "--list", tag).splitlines():
        abort(f"tag {tag} already exists")
    print(f"Release version: {version}")

    previous_head = git("rev-parse", "HEAD")
    released = False
    try:
        # Clean before committing: only the uv build (hatch-vcs) depends on
        # the tag, so the release commit can be made from a clean slate.
        clean()
        set_js_version(version)
        run(["git", "add", "paskia-js/package.json"])
        run(["git", "commit", "-m", f"Release {version}"])
        run(["git", "tag", tag])
        released = True

        # uv build runs the hatch hook that builds paskia-js and the Vue
        # frontend into paskia/frontend-build with fresh dependencies.
        run(["uv", "build"])
        # Explicit paskia-js build: verifies the package standalone and
        # leaves paskia-js/dist ready for npm publish.
        run(["npm", "install"], cwd=REPO_ROOT / "paskia-js")
        run(["npm", "run", "build"], cwd=REPO_ROOT / "paskia-js")
    except BaseException:
        if released:
            print("Build failed; rolling back the release commit and tag.", file=sys.stderr)
            subprocess.run(["git", "tag", "-d", tag], cwd=REPO_ROOT, check=False)  # noqa: S603
            # The tree was clean before the release commit, so a hard reset
            # back to it is safe.
            subprocess.run(["git", "reset", "--hard", previous_head], cwd=REPO_ROOT, check=False)  # noqa: S603
        raise

    # Push the release commit to the tracking remote, then the new tag.
    # Not rolled back on failure: the local release is intact, just push again.
    try:
        run(["git", "push"])
        run(["git", "push", "--tags"])
    except subprocess.CalledProcessError:
        abort("push failed; the release commit and tag exist locally, push manually")

    print(f"\nBuild completed successfully for version {version}.")
    print("To publish, review the artifacts and run:")
    print("\nuv publish && cd paskia-js && npm publish")


if __name__ == "__main__":
    main()
