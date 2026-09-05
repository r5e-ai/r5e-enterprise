import importlib
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
ci = importlib.import_module("prepare-ci-sources")
release_snapshot = importlib.import_module("release-snapshot")
safety = ci.load_release_policy(ci.TOOL_ENTERPRISE)


class PublicTreeParityTest(unittest.TestCase):
    def test_ci_and_jj_archives_match_with_public_exclusions(self):
        files = {
            "README.md": ("100644", b"public\n"),
            "bin/check": ("100755", b"#!/bin/sh\n"),
            "link": ("120000", b"README.md"),
            ".gitlab/ci/private-deploy.yml": ("100644", b"private pipeline\n"),
            ".release-forbidden": ("100644", b"pattern # reason\n"),
            "specs/010-gateway-api-group/spec.md": ("100644", b"published record\n"),
        }
        raw = b"".join(
            f"{mode} blob {path}\t{path}\0".encode()
            for path, (mode, _) in files.items()
        )
        entries = b"".join(
            f"{path}\0{'symlink' if mode == '120000' else 'file'}\0{'true' if mode == '100755' else 'false'}\0".encode()
            for path, (mode, _) in files.items()
        )

        def jj(_repo, *args):
            if "log" in args:
                return b"a" * 40
            if "list" in args:
                return entries
            if args[-2:] == ("git", "root"):
                return b"/fixture/.jj/repo/store/git\n"
            mode, data = files[args[-1]]
            # `jj file show` prints nothing for a symlink; the packer reads
            # the target from the Git backend instead.
            return b"" if mode == "120000" else data

        def git(_git_dir, *args):
            self.assertEqual(args[:2], ("cat-file", "blob"))
            return files[args[2].split(":", 1)[1]][1]

        exclude = lambda path: safety.public_tree_excluded("r5e-enterprise", path) is not None
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(ci, "git", return_value=raw), patch.object(
                ci, "git_blob", side_effect=lambda _repo, obj: files[obj][1]
            ), patch.object(release_snapshot, "jj", side_effect=jj), patch.object(
                release_snapshot, "git", side_effect=git
            ):
                ci.snapshot(root, "a" * 40, root / "ci.gz", safety.refused, exclude)
                release_snapshot.snapshot(root, root / "jj.gz", reject=safety.refused, exclude=exclude)
            self.assertEqual((root / "ci.gz").read_bytes(), (root / "jj.gz").read_bytes())
            with tarfile.open(root / "ci.gz", "r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    ["README.md", "bin/check", "link", "specs/010-gateway-api-group/spec.md"],
                )

    def test_forbidden_path_is_rejected_even_when_public_policy_excludes_it(self):
        path = ".gitlab/ci/deploy.key"
        self.assertIsNotNone(safety.public_tree_excluded("r5e-enterprise", path))
        raw = f"100644 blob abc\t{path}\0".encode()
        with patch.object(ci, "git", return_value=raw):
            with self.assertRaisesRegex(ValueError, "runtime state, secrets or internal-shaped"):
                ci.tree_records(Path("unused"), "a" * 40, safety.refused, lambda _path: True)

    def test_the_tripwire_stops_the_ci_snapshot_and_names_the_path(self):
        raw = b"100644 blob abc\tREADME.md\x00100644 blob def\tHANDOFF.md\x00"
        with patch.object(ci, "git", return_value=raw):
            with self.assertRaisesRegex(ValueError, r"HANDOFF\.md: HANDOFF\.md left the tree"):
                ci.tree_records(Path("unused"), "a" * 40, safety.refused)

    def test_context_applies_configured_content_gate_before_publication(self):
        commit = "a" * 40
        pins = {name: {"commit": commit, "url": "https://example.test/repo.git"} for name in ci.COMPANIONS}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".release-forbidden").write_text("PRIVATE_SENTINEL # fixture infrastructure\n")

            def snapshot(_repo, _commit, output, _reject, exclude=None):
                with tarfile.open(output, "w:gz") as archive:
                    data = b"PRIVATE_SENTINEL"
                    info = tarfile.TarInfo("README.md")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            with patch.object(ci, "TOOL_ENTERPRISE", root), patch.object(
                ci, "load_release_policy", return_value=safety
            ), patch.object(ci, "read_pins", return_value=pins), patch.object(
                ci, "require_commit", return_value=commit
            ), patch.object(ci, "snapshot", side_effect=snapshot):
                with self.assertRaisesRegex(ValueError, "infrastructure"):
                    ci.prepare_context(
                        enterprise=root, enterprise_commit=commit, pin_file=root / "pins.json",
                        output=root / "output", overrides={name: root for name in ci.COMPANIONS},
                    )
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
