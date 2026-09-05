#!/usr/bin/env python3
"""Freeze JJ source and its manifest under the published public-tree policy."""

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile

# The tree is the release.
#
# What is tracked in this repository is what is published. Material that
# is internal to the operator — deployment topology, working plans, agent
# tooling, handoff notes, the state of one deployment — is not kept here;
# it lives in the private handbook. So the packer does not carry a list of
# directories that are "not really part of it". It has three small rules,
# and they do different things.
#
# `refused` STOPS the release. Two shapes: a tracked path that looks like
# runtime state or a private key (`release_forbidden`), and a tracked path
# whose name says it holds internal material (`internal_shaped`, the
# tripwire). Nobody decided to publish either, so the right answer is to
# stop and name the path.
#
# `public_tree_excluded` OMITS. Only what cannot be tracked in a public
# tree in the first place: the content gate's own patterns, the operator's
# private CI, and build output. That is the whole list.
#
# `content_forbidden` is the backstop: after the omissions are applied,
# the surviving bytes are searched for the strings that identify this
# operator's infrastructure. A hit fails the build. It is deliberately
# dumb and deliberately not a judgement call.
#
# `docs/release/public-tree.md` says the same thing in prose; keep them in
# step (the unit test checks that the page names every path below).

# Tracked, and dropped from the archive before the manifest hash is
# computed, so the manifest covers exactly what is published.
PUBLIC_TREE_OMITTED = {
    ".release-forbidden": "the content gate's own patterns: the strings that must not be published cannot be one of the published files",
    ".gitlab/": "not in the published tree; an operator's own private deploy include (`.gitlab/ci/private-deploy.yml`), which `.gitlab-ci.yml` picks up only when present in that operator's checkout",
}

# Never tracked; omitted defensively so a stray `jj file track` cannot ship
# a build.
BUILD_OUTPUT = ("_build/", "deps/", "node_modules/", "target/")

# The tripwire. These paths used to hold internal material and left the
# tree (2026-09-05). If one is tracked again the release stops, because the
# decision was that they leave the repository, not that a filter hides
# them.
INTERNAL_SHAPED = {
    "infra/": "deployment topology: Helm values, Terraform, hostnames",
    ".specify/": "spec-kit working state and operations notes",
    "design/": "UI design briefs and design-tool source (the UI's tokens live at ui/design-tokens.json)",
    "docs/superpowers/": "agent-plugin working state and plans",
    "HANDOFF.md": "internal handoff notes",
    "r5e-PRD.md": "internal product planning",
    "tmp/": "scratch",
}

# The content gate's patterns are **not** in this file, and cannot be: this
# script is published, and the strings it searches for are precisely the
# strings that must not appear in a published file. They live in
# `.release-forbidden` at the repository root — one extended-regex per
# line, `#` to end of line for the reason — which is itself omitted from
# the public tree.
#
# A fork therefore gets the mechanism and an empty list, and is told so
# rather than left believing a gate ran. Add your own file to arm it.
FORBIDDEN_CONTENT_FILE = ".release-forbidden"


def forbidden_patterns(enterprise):
    """`[(compiled, reason)]` from `.release-forbidden`, or `[]` when absent."""
    path = enterprise / FORBIDDEN_CONTENT_FILE
    if not path.exists():
        return []

    patterns = []
    for line in path.read_text().splitlines():
        source, _, reason = line.partition("#")
        source = source.strip()
        if source:
            patterns.append((re.compile(source.encode()), reason.strip() or "a forbidden string"))
    return patterns


def _under(path, entry):
    """`entry` names `path` exactly, or is a `dir/` prefix of it."""
    return path == entry or (entry.endswith("/") and path.startswith(entry))


def release_forbidden(path):
    """Reject deployment state and secret-shaped files from source releases."""
    parts = Path(path).parts
    for part in parts:
        if part == ".r5e" or part.startswith((".r5e.", ".r5e-")):
            return True
        if part in {".git", ".jj", "secrets"}:
            return True

    name = parts[-1] if parts else ""
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    return Path(name).suffix.lower() in {".key", ".pem", ".p12", ".pfx", ".jks"}


def internal_shaped(path):
    """The reason a tracked `path` trips the wire, or None when it does not."""
    for entry, reason in INTERNAL_SHAPED.items():
        if _under(path, entry):
            return f"{entry} left the tree on 2026-09-05 ({reason})"
    return None


def refused(path):
    """Why the release must stop for `path`, or a false value when it may go on.

    The snapshotters treat any true value as a rejection and print it, so a
    tripwire hit names the path and the reason.
    """
    if release_forbidden(path):
        return "runtime state or a secret-shaped file"
    return internal_shaped(path)


def public_tree_excluded(repo, path):
    """The reason `path` is not published, or None when it is.

    Only the enterprise tree has omissions: core and kernel are published
    whole. Returning the reason rather than a boolean is deliberate — the
    caller prints it, and `docs/release/public-tree.md` is the same list.
    """
    if repo != "r5e-enterprise":
        return None

    for entry, reason in PUBLIC_TREE_OMITTED.items():
        if _under(path, entry):
            return reason

    if any(_under(path, entry) for entry in BUILD_OUTPUT) or any(
        part in ("node_modules", "target") for part in Path(path).parts[:-1]
    ):
        return "build output"

    return None


def content_forbidden(context, patterns):
    """Every published byte, searched for this operator's infrastructure.

    Returns a sorted list of `path:line: reason` strings. Binary files are
    searched too — the patterns are ASCII, and a hit inside an image would
    still be a hit.
    """
    findings = []
    for path in sorted(context.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        for pattern, reason in patterns:
            if not pattern.search(data):
                continue
            relative = path.relative_to(context).as_posix()
            for number, line in enumerate(data.split(b"\n"), start=1):
                if pattern.search(line):
                    findings.append(f"{relative}:{number}: {reason}")
    return sorted(findings)


def archive_context(context, output):
    """Write a byte-reproducible archive of an already frozen context."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{output.name}.", dir=output.parent, delete=False
    ) as raw:
        temporary = Path(raw.name)
        try:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for path in sorted(
                        context.rglob("*"), key=lambda item: item.relative_to(context).as_posix()
                    ):
                        relative = path.relative_to(context).as_posix()
                        metadata = path.lstat()
                        info = tarfile.TarInfo(relative)
                        info.mtime = info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        if stat.S_ISDIR(metadata.st_mode):
                            info.type = tarfile.DIRTYPE
                            info.mode = 0o755
                            archive.addfile(info)
                        elif stat.S_ISLNK(metadata.st_mode):
                            info.type = tarfile.SYMTYPE
                            info.linkname = os.readlink(path)
                            info.mode = 0o777
                            archive.addfile(info)
                        elif stat.S_ISREG(metadata.st_mode):
                            info.mode = stat.S_IMODE(metadata.st_mode)
                            info.size = metadata.st_size
                            with path.open("rb") as source:
                                archive.addfile(info, source)
                        else:
                            raise ValueError(f"cannot release special file: {path}")
            temporary.replace(output)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise


def main():
    enterprise = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=enterprise / ".release-context")
    parser.add_argument(
        "--archive",
        type=Path,
        help="also write a reproducible tar.gz containing the complete three-source context",
    )
    parser.add_argument("--core", type=Path, default=enterprise.parent / "r5e-core")
    parser.add_argument("--kernel", type=Path, default=enterprise.parent / "r5e-kernel")
    for name in ("enterprise", "core", "kernel"):
        parser.add_argument(f"--{name}-revision", default="@")
    args = parser.parse_args()
    output = args.output.resolve()
    coordinated_archive = args.archive.resolve() if args.archive else None
    if output.exists():
        parser.error(f"output already exists: {output}; choose a fresh directory")
    if coordinated_archive and coordinated_archive.is_relative_to(output):
        parser.error("archive must be outside the output context")

    module_spec = importlib.util.spec_from_file_location("release_snapshot", enterprise / "scripts/release-snapshot.py")
    snapshot = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(snapshot)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Stage beside the destination; publish a complete context with one rename.
    with tempfile.TemporaryDirectory(prefix="r5e-release-", dir=output.parent) as temporary:
        root = Path(temporary)
        context = root / "context"
        context.mkdir()
        manifest = {"format": "r5e-source-snapshot/v1", "repositories": {}}
        for name, repo, revision in (
            ("r5e-core", args.core, args.core_revision),
            ("r5e-kernel", args.kernel, args.kernel_revision),
            ("r5e-enterprise", enterprise, args.enterprise_revision),
        ):
            component_archive = root / f"{name}.tar.gz"
            commit = snapshot.snapshot(
                repo.resolve(),
                component_archive,
                revision,
                reject=refused,
                exclude=lambda path, repo=name: public_tree_excluded(repo, path) is not None,
            )
            destination = context / name
            destination.mkdir()
            with tarfile.open(component_archive, "r:gz") as source:
                source.extractall(destination, filter="data")
            manifest["repositories"][name] = {
                "commit": commit,
                "archiveSha256": hashlib.sha256(component_archive.read_bytes()).hexdigest(),
            }
        # The backstop, over the tree as published: exclusions applied,
        # nothing else. It runs before the archive is written, so a release
        # that would carry this operator's infrastructure never becomes an
        # artifact anyone has to remember to delete.
        patterns = forbidden_patterns(enterprise)
        if not patterns:
            print(
                f"note: no {FORBIDDEN_CONTENT_FILE} at {enterprise}; "
                "the published bytes were not searched for forbidden content"
            )

        findings = content_forbidden(context, patterns)
        if findings:
            listed = "\n  ".join(findings)
            raise ValueError(
                "refusing release: the public tree still names this operator's "
                f"infrastructure:\n  {listed}\n"
                "Remove the reference: the tree is the release, and a file that names "
                "this operator's infrastructure does not belong in it."
            )

        (context / "repos.lock.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        shutil.copyfile(context / "r5e-enterprise/docker-compose/fold-context.dockerignore", context / ".dockerignore")
        if coordinated_archive:
            archive_context(context, coordinated_archive)
        context.rename(output)
    print(output)
    if coordinated_archive:
        print(f"archive: {coordinated_archive}")
        print(
            f"archiveSha256: {hashlib.sha256(coordinated_archive.read_bytes()).hexdigest()}"
        )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
