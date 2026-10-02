#!/usr/bin/env python3
"""Validate stable releases and their built assets."""
import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu",
)
STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def validate_version(tag=None, root=ROOT, previous=None):
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    version = manifest["package"]["version"]
    if not STABLE.fullmatch(version):
        raise ValueError("Production releases require a stable X.Y.Z Cargo version")
    packages = tomllib.loads((root / "Cargo.lock").read_text())["package"]
    package = next(p for p in packages if p["name"] == "dott" and "source" not in p)
    if package["version"] != version:
        raise ValueError("Cargo.lock's dott version does not match Cargo.toml")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"Tag {tag!r} does not match Cargo.toml v{version}")
    if previous is not None:
        old = previous.removeprefix("v")
        if not STABLE.fullmatch(old):
            raise ValueError("Previous release must have a stable vX.Y.Z tag")
        if tuple(map(int, version.split('.'))) <= tuple(map(int, old.split('.'))):
            raise ValueError(f"New version {version} must be newer than published {previous}")
    return version


def verify_assets(directory):
    checksums = {}
    for target in TARGETS:
        name = f"dott-{target}.tar.gz"
        archive = directory / name
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        fields = (directory / f"{name}.sha256").read_text().split()
        if fields != [checksum, name]:
            raise ValueError(f"Invalid checksum sidecar for {name}")
        with tarfile.open(archive) as bundle:
            members = bundle.getmembers()
            if (len(members) != 1 or members[0].name != "dott"
                    or not members[0].isfile() or not members[0].mode & 0o111):
                raise ValueError(f"{name} must contain exactly one executable file named dott")
        checksums[target] = checksum
    return checksums


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "assets"])
    parser.add_argument("--tag")
    parser.add_argument("--previous", help="Latest published tag; reject non-increasing releases")
    parser.add_argument("--assets", type=Path)
    args = parser.parse_args()
    try:
        version = validate_version(args.tag, previous=args.previous)
        if args.command == "assets":
            if not args.assets or not args.tag:
                parser.error("assets requires --tag and --assets")
            verify_assets(args.assets)
        print(f"Validated dott {version}")
    except (ValueError, OSError, KeyError, StopIteration, tarfile.TarError) as error:
        parser.exit(1, f"Release validation failed: {error}\n")


if __name__ == "__main__":
    main()
