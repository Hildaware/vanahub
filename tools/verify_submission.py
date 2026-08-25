#!/usr/bin/env python3
"""Verify that a catalog submitter is authorized by the source repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from pathlib import Path


SOURCE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/?$")
RELEASE = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/releases/download/[^/]+/[^/]+$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
PRIVILEGED_SOURCES = {"vanahub": "https://github.com/Hildaware/vanahub"}


def semver_greater(candidate: str, previous: str) -> bool:
    def parse(value: str):
        match = SEMVER.fullmatch(value)
        if not match:
            raise ValueError(f"invalid SemVer: {value}")
        core = tuple(int(part) for part in match.groups()[:3])
        prerelease = match.group(4)
        identifiers = [] if prerelease is None else prerelease.split(".")
        return core, identifiers, prerelease is None

    left_core, left_pre, left_stable = parse(candidate)
    right_core, right_pre, right_stable = parse(previous)
    if left_core != right_core:
        return left_core > right_core
    if left_stable != right_stable:
        return left_stable
    if left_stable:
        return False
    for left, right in zip(left_pre, right_pre):
        if left == right:
            continue
        left_numeric, right_numeric = left.isdigit(), right.isdigit()
        if left_numeric and right_numeric:
            return int(left) > int(right)
        if left_numeric != right_numeric:
            return not left_numeric
        return left > right
    return len(left_pre) > len(right_pre)


def github_json(url: str) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "vanahub-admission/1"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=20) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--previous-root", type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    match = SOURCE.fullmatch(manifest.get("sourceUrl", ""))
    if not match:
        raise SystemExit("sourceUrl must be a public GitHub repository")
    owner, repository = match.groups()
    privileged_source = PRIVILEGED_SOURCES.get(manifest.get("id"))
    if privileged_source and manifest.get("sourceUrl", "").rstrip("/").casefold() != privileged_source.casefold():
        raise SystemExit("privileged package ID is reserved for its official source repository")
    release = RELEASE.fullmatch(manifest.get("downloadUrl", ""))
    if not release or tuple(part.casefold() for part in release.groups()) != (owner.casefold(), repository.casefold()):
        raise SystemExit("downloadUrl must be a GitHub Release asset from sourceUrl")
    if args.previous_root:
        previous_path = args.previous_root / manifest.get("id", "") / "manifest.json"
        if previous_path.exists():
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
            try:
                newer = semver_greater(manifest.get("version", ""), previous.get("version", ""))
            except ValueError as exc:
                raise SystemExit(str(exc)) from exc
            if not newer:
                raise SystemExit("updates must increase the package SemVer")
    metadata = github_json(f"https://api.github.com/repos/{owner}/{repository}")
    default_branch = metadata["default_branch"]
    authorization_url = f"https://raw.githubusercontent.com/{owner}/{repository}/{default_branch}/.vanahub.json"
    authorization = github_json(authorization_url)
    if authorization.get("schemaVersion") != 1:
        raise SystemExit("source .vanahub.json has an unsupported schema")
    package = authorization.get("packages", {}).get(manifest.get("id"))
    if not isinstance(package, dict):
        raise SystemExit("source repository does not authorize this package id")
    authorized = {name.casefold() for name in package.get("maintainers", [])}
    declared = {name.casefold() for name in manifest.get("maintainers", [])}
    if args.actor.casefold() not in authorized:
        raise SystemExit("pull-request actor is not an authorized maintainer")
    if not declared or not declared.issubset(authorized):
        raise SystemExit("catalog maintainers exceed source authorization")
    print(f"authorized {args.actor} for {manifest['id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
