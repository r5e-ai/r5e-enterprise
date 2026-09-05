#!/usr/bin/env python3
"""Materialize the exact three-source release context from Git commits."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import os
import subprocess
import tarfile
import tempfile


COMMIT = re.compile(r"[0-9a-f]{40}")
COMPANIONS = ("r5e-core", "r5e-kernel")
TOOL_ENTERPRISE = Path(__file__).resolve().parent.parent


def git(repo, *args, input=None):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], input=input, stderr=subprocess.STDOUT
    )


def load_release_policy(enterprise):
    """Reuse the release packer's rejection, public-tree and content policies."""
    path = enterprise / "scripts" / "prepare-release.py"
    module_spec = importlib.util.spec_from_file_location("prepare_release", path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


def load_release_safety(enterprise):
    """Compatibility accessor for the tracked-path rejection (state, secrets, tripwire)."""
    return load_release_policy(enterprise).refused


def read_pins(path):
    pins = json.loads(path.read_text())
    if pins.get("format") != "r5e-release-dependencies/v1":
        raise ValueError(f"unsupported dependency lock format in {path}")
    repositories = pins.get("repositories")
    if not isinstance(repositories, dict) or set(repositories) != set(COMPANIONS):
        raise ValueError("dependency lock must contain exactly r5e-core and r5e-kernel")
    for name in COMPANIONS:
        record = repositories[name]
        if not isinstance(record, dict) or not COMMIT.fullmatch(record.get("commit", "")):
            raise ValueError(f"{name} must have a full lowercase Git commit id")
        if not isinstance(record.get("url"), str) or not record["url"].startswith("https://"):
            raise ValueError(f"{name} must have an https source URL")
    return repositories


def require_commit(repo, expected, name):
    try:
        resolved = git(repo, "rev-parse", "--verify", f"{expected}^{{commit}}").decode().strip()
    except subprocess.CalledProcessError as error:
        detail = error.output.decode(errors="replace").strip()
        raise ValueError(f"{name} does not contain pinned commit {expected}: {detail}") from error
    if resolved != expected:
        raise ValueError(f"{name} resolved {expected} to unexpected commit {resolved}")
    return resolved


def companion_url(url):
    """The companion's fetch URL, or the same path under R5E_COMPANION_GIT_BASE.

    The pin file records the public URL. A staging run (private mirrors that
    hold the same commits) sets the base; the commit stays pinned either way,
    so a different base can only change *where* the exact commit is fetched
    from, never *which* commit is built.
    """
    base = os.environ.get("R5E_COMPANION_GIT_BASE", "").strip().rstrip("/")
    if not base:
        return url
    return f"{base}/{url.rstrip('/').rsplit('/', 1)[1]}"


def fetch_exact(name, record, root):
    repo = root / f"{name}.git"
    subprocess.run(["git", "init", "--bare", "--quiet", str(repo)], check=True)
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                companion_url(record["url"]),
                record["commit"],
            ],
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise ValueError(
            f"cannot fetch pinned {name} commit {record['commit']} from {companion_url(record['url'])}"
        ) from error
    require_commit(repo, record["commit"], name)
    return repo


def tree_records(repo, commit, reject, exclude=None):
    raw = git(repo, "ls-tree", "-rz", "--full-tree", commit)
    records = []
    rejected = []
    for encoded in raw.split(b"\0"):
        if not encoded:
            continue
        header, encoded_path = encoded.split(b"\t", 1)
        mode, kind, object_id = header.decode().split()
        path = encoded_path.decode()
        parts = PurePosixPath(path).parts
        if not parts or path.startswith("/") or ".." in parts:
            raise ValueError(f"unsafe repository path: {path}")
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise ValueError(f"cannot release Git object {kind} mode {mode}: {path}")
        reason = reject(path)
        if reason:
            rejected.append(path if reason is True else f"{path}: {reason}")
        records.append((path, mode, object_id))
    if rejected:
        listed = "\n  ".join(sorted(rejected))
        raise ValueError(
            "refusing release snapshot: tracked paths that are runtime state, "
            f"secrets or internal-shaped:\n  {listed}"
        )
    return sorted(record for record in records if not exclude or not exclude(record[0]))


def git_blob(repo, object_id):
    return git(repo, "cat-file", "blob", object_id)


def snapshot(repo, commit, output, reject, exclude=None):
    records = tree_records(repo, commit, reject, exclude)
    workers = min(32, max(4, len(records)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        contents = pool.map(lambda record: git_blob(repo, record[2]), records)
        with output.open("wb") as raw, gzip.GzipFile(
            fileobj=raw, mode="wb", filename="", mtime=0
        ) as zipped:
            with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for (path, mode, _object_id), data in zip(records, contents, strict=True):
                    info = tarfile.TarInfo(path)
                    info.mtime = info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    if mode == "120000":
                        info.type = tarfile.SYMTYPE
                        info.linkname = data.decode()
                        info.mode = 0o777
                        archive.addfile(info)
                    else:
                        info.mode = 0o755 if mode == "100755" else 0o644
                        info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))


def prepare_context(
    *, enterprise, enterprise_commit, pin_file, output, metadata=None, overrides=None
):
    enterprise = enterprise.resolve()
    output = output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}; choose a fresh directory")
    if not COMMIT.fullmatch(enterprise_commit):
        raise ValueError("--enterprise-commit must be a full lowercase Git commit id")
    pins = read_pins(pin_file.resolve())
    # The helper and the release packer ship together in the CI commit. Use
    # that reviewed code for the boundary; --enterprise-source is only a Git
    # object database and its checked-out files are never an input.
    safety = load_release_policy(TOOL_ENTERPRISE)
    overrides = overrides or {}
    require_commit(enterprise, enterprise_commit, "r5e-enterprise")
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="r5e-ci-sources-", dir=output.parent) as temporary:
        root = Path(temporary)
        context = root / "context"
        context.mkdir()
        sources = {"r5e-enterprise": (enterprise, enterprise_commit)}
        for name in COMPANIONS:
            repo = overrides.get(name)
            if repo is None:
                repo = fetch_exact(name, pins[name], root)
            else:
                repo = Path(repo).resolve()
                require_commit(repo, pins[name]["commit"], name)
            sources[name] = (repo, pins[name]["commit"])

        manifest = {"format": "r5e-source-snapshot/v1", "repositories": {}}
        for name in ("r5e-core", "r5e-kernel", "r5e-enterprise"):
            repo, commit = sources[name]
            component_archive = root / f"{name}.tar.gz"
            snapshot(
                repo, commit, component_archive, safety.refused,
                exclude=lambda path, repo=name: safety.public_tree_excluded(repo, path) is not None,
            )
            destination = context / name
            destination.mkdir()
            with tarfile.open(component_archive, "r:gz") as source:
                source.extractall(destination, filter="data")
            manifest["repositories"][name] = {
                "commit": commit,
                "archiveSha256": hashlib.sha256(component_archive.read_bytes()).hexdigest(),
            }

        # Search the same published tree with the packer's configured gate,
        # before publishing the context or its manifest.
        patterns = safety.forbidden_patterns(TOOL_ENTERPRISE)
        if not patterns:
            print(
                f"note: no {safety.FORBIDDEN_CONTENT_FILE} at {TOOL_ENTERPRISE}; "
                "the published bytes were not searched for forbidden content"
            )
        findings = safety.content_forbidden(context, patterns)
        if findings:
            listed = "\n  ".join(findings)
            raise ValueError(
                "refusing release: the public tree still names this operator's "
                f"infrastructure:\n  {listed}"
            )

        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        (context / "repos.lock.json").write_bytes(manifest_bytes)
        shutil.copyfile(
            context / "r5e-enterprise" / "docker-compose" / "fold-context.dockerignore",
            context / ".dockerignore",
        )
        source_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        context.rename(output)

    if metadata:
        metadata = metadata.resolve()
        metadata.parent.mkdir(parents=True, exist_ok=True)
        metadata.write_text(
            f"R5E_SOURCE_SHA256={source_sha256}\n"
            f"R5E_ENTERPRISE_COMMIT={enterprise_commit}\n"
            f"R5E_CORE_COMMIT={pins['r5e-core']['commit']}\n"
            f"R5E_KERNEL_COMMIT={pins['r5e-kernel']['commit']}\n"
        )
    return manifest, source_sha256


def main():
    enterprise = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--enterprise-source", type=Path, default=enterprise)
    parser.add_argument("--enterprise-commit", required=True)
    parser.add_argument("--pin-file", type=Path, default=enterprise / "release-dependencies.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--core-source", type=Path)
    parser.add_argument("--kernel-source", type=Path)
    args = parser.parse_args()
    overrides = {
        name: source
        for name, source in (
            ("r5e-core", args.core_source),
            ("r5e-kernel", args.kernel_source),
        )
        if source is not None
    }
    manifest, source_sha256 = prepare_context(
        enterprise=args.enterprise_source,
        enterprise_commit=args.enterprise_commit,
        pin_file=args.pin_file,
        output=args.output,
        metadata=args.metadata,
        overrides=overrides,
    )
    print(args.output.resolve())
    print(f"sourceSha256: {source_sha256}")
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
