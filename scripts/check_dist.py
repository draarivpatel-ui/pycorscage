"""Inspect built wheel and sdist artifacts with the standard library only."""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


def fail(message: str) -> int:
    print("dist check failed: " + message, file=sys.stderr)
    return 1


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    dist = root / "dist"
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1:
        return fail("expected exactly one wheel, found " + str(len(wheels)))
    if len(sdists) != 1:
        return fail("expected exactly one sdist, found " + str(len(sdists)))

    wheel = wheels[0]
    with zipfile.ZipFile(str(wheel), "r") as archive:
        wheel_names = archive.namelist()
    if "pycorscage/py.typed" not in wheel_names:
        return fail("py.typed is missing from the wheel")
    if any(name.startswith("tests/") or "/tests/" in name for name in wheel_names):
        return fail("tests are present in the wheel")
    if any("__pycache__" in name or name.endswith((".pyc", ".pyo")) for name in wheel_names):
        return fail("bytecode cache files are present in the wheel")
    if not any(name.startswith("pycorscage/") and name.endswith(".py") for name in wheel_names):
        return fail("package Python files are missing from the wheel")

    sdist = sdists[0]
    with tarfile.open(str(sdist), "r:gz") as archive:
        sdist_names = archive.getnames()
    if not any(name.endswith("/src/pycorscage/py.typed") for name in sdist_names):
        return fail("py.typed is missing from the sdist")
    if any("__pycache__" in name or name.endswith((".pyc", ".pyo")) for name in sdist_names):
        return fail("bytecode cache files are present in the sdist")

    print("wheel files: " + str(len(wheel_names)))
    print("sdist files: " + str(len(sdist_names)))
    print("dist check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
