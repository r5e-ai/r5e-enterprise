#!/usr/bin/env python3
"""Recompute each frozen source tree's archive digest and check it against the manifest."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tarfile


class Digest:
    """Somewhere for the gzip writer to put bytes when only the digest is wanted."""

    def __init__(self):
        self.hash = hashlib.sha256()

    def write(self, data):
        self.hash.update(data)
        return len(data)

    def flush(self):
        pass


def tree_entries(root):
    """Every file and symlink under root, repo-relative, in the order the archive lists them."""
    entries = []
    pending = [root]
    while pending:
        for item in pending.pop().iterdir():
            metadata = item.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(item)
            elif stat.S_ISLNK(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
                entries.append((item.relative_to(root).as_posix(), item, metadata))
            else:
                raise ValueError(f"cannot verify special file: {item}")
    entries.sort(key=lambda entry: entry[0])
    return entries


def tree_digest(root):
    """Rebuild the component archive release-snapshot.py wrote for this tree, and hash it."""
    sink = Digest()
    with gzip.GzipFile(fileobj=sink, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for relative, path, metadata in tree_entries(root):
                info = tarfile.TarInfo(relative)
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                if stat.S_ISLNK(metadata.st_mode):
                    info.type = tarfile.SYMTYPE
                    info.linkname = os.readlink(path)
                    info.mode = 0o777
                    archive.addfile(info)
                else:
                    info.mode = 0o755 if metadata.st_mode & stat.S_IXUSR else 0o644
                    info.size = metadata.st_size
                    with path.open("rb") as source:
                        archive.addfile(info, source)
    return sink.hash.hexdigest()


def verify(context, manifest_path, report=print):
    """Check every tree the manifest names. Returns the names that did not verify."""
    manifest = json.loads(manifest_path.read_text())
    repositories = manifest["repositories"]
    failures = []
    for name in sorted(repositories):
        root = context / name
        if root.is_symlink() or not root.is_dir():
            report(f"{name}: no source tree at {root}")
            failures.append(name)
            continue
        recorded = repositories[name]["archiveSha256"]
        try:
            recomputed = tree_digest(root)
        except ValueError as refusal:
            report(f"{name}: {refusal}")
            failures.append(name)
            continue
        matched = recomputed == recorded
        report(
            f"{name}: recomputed={recomputed} manifest={recorded} "
            f"match={'yes' if matched else 'no'}"
        )
        if not matched:
            failures.append(name)
    return failures


def main():
    # Run from an extracted context the script ships inside: <context>/r5e-enterprise/scripts/.
    default_context = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "context",
        nargs="?",
        type=Path,
        default=default_context,
        help="directory holding the source trees side by side (default: %(default)s)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        help="repos.lock.json to check against (default: repos.lock.json in the context)",
    )
    args = parser.parse_args()
    context = args.context.resolve()
    manifest_path = (args.manifest if args.manifest else context / "repos.lock.json").resolve()
    if not manifest_path.is_file():
        print(f"no manifest at {manifest_path}", file=sys.stderr)
        return 2
    failures = verify(context, manifest_path)
    if failures:
        print(
            f"source digests do not match {manifest_path}: {', '.join(failures)}",
            file=sys.stderr,
        )
        return 1
    print(f"all source digests match {manifest_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
