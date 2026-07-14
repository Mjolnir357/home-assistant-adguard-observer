#!/usr/bin/env python3
"""Require Home Assistant app changes to increase the manifest version."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

APP_DIRECTORY = "adguard_dns_observer/"
CONFIG_PATH = f"{APP_DIRECTORY}config.yaml"
VERSION_PATTERN = re.compile(r'^version:\s*["\']?([0-9]+(?:\.[0-9]+){2})["\']?\s*$', re.MULTILINE)


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} failed")
    return result.stdout


def parse_version(text: str) -> tuple[int, int, int]:
    match = VERSION_PATTERN.search(text)
    if not match:
        raise ValueError("config.yaml does not contain a semantic app version")
    return tuple(int(part) for part in match.group(1).split("."))  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", required=True)
    args = parser.parse_args(argv)

    committed_paths = {
        line.strip()
        for line in git("diff", "--name-only", f"{args.base_ref}...HEAD").splitlines()
        if line.strip()
    }
    working_tree_paths = {
        line.strip()
        for arguments in (("diff", "--name-only"), ("diff", "--cached", "--name-only"))
        for line in git(*arguments).splitlines()
        if line.strip()
    }
    changed_paths = committed_paths | working_tree_paths
    if not any(path.startswith(APP_DIRECTORY) for path in changed_paths):
        print("No Home Assistant app files changed; version bump not required")
        return 0

    current_version = parse_version(Path(CONFIG_PATH).read_text(encoding="utf-8"))
    base_config = git("show", f"{args.base_ref}:{CONFIG_PATH}", check=False)
    if not base_config:
        print(f"New app detected at version {'.'.join(map(str, current_version))}")
        return 0

    base_version = parse_version(base_config)
    if current_version <= base_version:
        print(
            "Home Assistant app files changed without increasing the version: "
            f"{'.'.join(map(str, base_version))} -> {'.'.join(map(str, current_version))}",
            file=sys.stderr,
        )
        return 1

    print(
        "Home Assistant app version increased: "
        f"{'.'.join(map(str, base_version))} -> {'.'.join(map(str, current_version))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
