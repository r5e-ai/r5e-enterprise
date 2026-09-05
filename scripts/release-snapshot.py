#!/usr/bin/env python3
"""Archive one JJ revision, never ignored files or a moving working directory."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile


def jj(repo, *args):
    return subprocess.check_output(["jj", "--no-pager", "-R", str(repo), *args], cwd=repo)


def git(git_dir, *args):
    return subprocess.check_output(["git", "--git-dir", str(git_dir), *args])


def symlink_target(repo, commit, path):
    """The link target of a tracked symlink at `commit`.

    `jj file show` refuses a symlink ("exists but is not a file") and prints
    nothing, which would archive an empty link target and leave the
    extracted tree with a different link than the one that was tracked.
    The Git backend stores the target as the blob's bytes, and JJ's commit
    id is the Git commit id, so read it the way prepare-ci-sources.py does.
    """
    git_dir = jj(repo, "--ignore-working-copy", "git", "root").decode().strip()
    return git(git_dir, "cat-file", "blob", f"{commit}:{path}")


def snapshot(repo, output, revision="@", reject=None, exclude=None):
    # Resolve once: subsequent commands must not snapshot concurrent edits.
    commit = jj(repo, "log", "--no-graph", "-r", revision, "-T", "commit_id").decode().strip()
    entries = jj(repo, "--ignore-working-copy", "file", "list", "-r", commit,
                 "-T", 'path ++ "\\0" ++ file_type ++ "\\0" ++ executable ++ "\\0"')
    fields = entries.split(b"\0")
    if fields[-1] != b"" or (len(fields) - 1) % 3:
        raise ValueError("unexpected JJ tree listing")
    output.parent.mkdir(parents=True, exist_ok=True)
    records = [
        tuple(part.decode() for part in fields[offset:offset + 3])
        for offset in range(0, len(fields) - 1, 3)
    ]
    records.sort(key=lambda record: record[0])
    if reject:
        rejected = []
        for path, _kind, _executable in records:
            reason = reject(path)
            if reason:
                rejected.append(path if reason is True else f"{path}: {reason}")
        if rejected:
            listed = "\n  ".join(rejected)
            raise ValueError(
                "refusing release snapshot: tracked paths that are runtime state, "
                f"secrets or internal-shaped:\n  {listed}"
            )

    # `reject` stops the release; `exclude` shapes it. A path the caller's
    # policy omits from the public tree is dropped here, before the archive
    # exists, so the manifest hash covers exactly what is published.
    if exclude:
        records = [record for record in records if not exclude(record[0])]

    # `jj file show` accepts only one unambiguous byte stream at a time. Read
    # resolved-tree entries concurrently so repositories with thousands of
    # files do not pay one process startup serially per file.
    workers = min(32, max(4, (os.cpu_count() or 1) * 2))

    def read(record):
        path, kind, _executable = record
        if kind == "symlink":
            return symlink_target(repo, commit, path)
        return jj(repo, "--ignore-working-copy", "file", "show", "-r", commit, "--", path)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        contents = pool.map(read, records)
        with output.open("wb") as raw, gzip.GzipFile(
            fileobj=raw, mode="wb", filename="", mtime=0
        ) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for (path, kind, executable), data in zip(records, contents, strict=True):
                    parts = PurePosixPath(path).parts
                    if not parts or path.startswith("/") or ".." in parts:
                        raise ValueError("unsafe repository path")
                    if kind not in ("file", "symlink"):
                        raise ValueError(f"cannot release {kind}: {path}")
                    info = tarfile.TarInfo(path)
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    if kind == "symlink":
                        info.type = tarfile.SYMTYPE
                        info.linkname = data.decode()
                        info.mode = 0o777
                        archive.addfile(info)
                    else:
                        info.mode = 0o755 if executable == "true" else 0o644
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
    return commit


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", default="@")
    args = parser.parse_args()
    print(snapshot(args.repo.resolve(), args.output.resolve(), args.revision))
