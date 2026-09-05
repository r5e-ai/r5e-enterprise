import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ENTERPRISE = Path(__file__).resolve().parents[2]
SCRIPT = ENTERPRISE / "scripts" / "verify-source-archive.py"
MODULE_SPEC = importlib.util.spec_from_file_location("verify_source_archive", SCRIPT)
VERIFY = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(VERIFY)


def archive_digest(entries):
    """Spell out the component archive by hand and hash it, as the manifest recorded it."""
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for name, mode, kind, payload in entries:
                info = tarfile.TarInfo(name)
                info.mtime = info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mode = mode
                if kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = payload
                    archive.addfile(info)
                else:
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
    return hashlib.sha256(raw.getvalue()).hexdigest()


class VerifySourceArchiveTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.context = Path(self.temporary.name) / "context"
        self.tree = self.context / "r5e-core"
        self.tree.mkdir(parents=True)
        # Neither the manifest nor a stray root file belongs to a tree.
        (self.context / "notes.txt").write_text("not part of any tree\n")

    def tearDown(self):
        self.temporary.cleanup()

    def write_file(self, relative, contents, executable=False):
        path = self.tree / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        path.chmod(0o755 if executable else 0o644)
        return path

    def write_manifest(self, digest, path=None):
        manifest = path if path else self.context / "repos.lock.json"
        manifest.write_text(
            json.dumps(
                {
                    "format": "r5e-source-snapshot/v1",
                    "repositories": {
                        "r5e-core": {"commit": "0" * 40, "archiveSha256": digest},
                    },
                }
            )
        )
        return manifest

    def run_script(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(self.context), *arguments],
            capture_output=True,
            text=True,
        )

    def two_file_tree(self):
        self.write_file("README.md", b"core\n")
        self.write_file("lib/one.ex", b"defmodule One do\nend\n")
        return archive_digest(
            [
                ("README.md", 0o644, "file", b"core\n"),
                ("lib/one.ex", 0o644, "file", b"defmodule One do\nend\n"),
            ]
        )

    def test_two_file_tree_matches_its_manifest(self):
        digest = self.two_file_tree()
        self.assertEqual(VERIFY.tree_digest(self.tree), digest)
        self.write_manifest(digest)
        finished = self.run_script()
        self.assertEqual(finished.returncode, 0, finished.stdout + finished.stderr)
        self.assertIn(f"recomputed={digest} manifest={digest} match=yes", finished.stdout)

    def test_manifest_outside_the_context_is_used(self):
        digest = self.two_file_tree()
        outside = self.write_manifest(digest, Path(self.temporary.name) / "repos.lock.json")
        finished = self.run_script("--manifest", str(outside))
        self.assertEqual(finished.returncode, 0, finished.stdout + finished.stderr)

    def test_executable_bit_changes_the_digest(self):
        self.write_file("run.sh", b"#!/bin/sh\n")
        plain = VERIFY.tree_digest(self.tree)
        self.write_file("run.sh", b"#!/bin/sh\n", executable=True)
        executable = VERIFY.tree_digest(self.tree)
        self.assertNotEqual(plain, executable)
        self.assertEqual(plain, archive_digest([("run.sh", 0o644, "file", b"#!/bin/sh\n")]))
        self.assertEqual(executable, archive_digest([("run.sh", 0o755, "file", b"#!/bin/sh\n")]))

    def test_mismatched_manifest_exits_non_zero(self):
        self.two_file_tree()
        self.write_manifest("f" * 64)
        finished = self.run_script()
        self.assertEqual(finished.returncode, 1)
        self.assertIn("match=no", finished.stdout)
        self.assertIn("r5e-core", finished.stderr)

    def test_symlink_round_trips(self):
        self.write_file("data.txt", b"payload\n")
        (self.tree / "link").symlink_to("data.txt")
        digest = archive_digest(
            [
                ("data.txt", 0o644, "file", b"payload\n"),
                ("link", 0o777, "symlink", "data.txt"),
            ]
        )
        self.assertEqual(VERIFY.tree_digest(self.tree), digest)

    def test_special_file_is_refused(self):
        self.write_file("data.txt", b"payload\n")
        os.mkfifo(self.tree / "pipe")
        with self.assertRaisesRegex(ValueError, "special file"):
            VERIFY.tree_digest(self.tree)


if __name__ == "__main__":
    unittest.main()
