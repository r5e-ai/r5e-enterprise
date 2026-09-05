import importlib
import importlib.util
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ENTERPRISE = Path(__file__).resolve().parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "prepare_release", ENTERPRISE / "scripts" / "prepare-release.py"
)
PREPARE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(PREPARE)
sys.path.insert(0, str(ENTERPRISE / "scripts"))
SNAPSHOT = importlib.import_module("release-snapshot")
PUBLIC_TREE_PAGE = (ENTERPRISE / "docs" / "release" / "public-tree.md").read_text()


class PublicTreePolicyTest(unittest.TestCase):
    """The tree is the release. The packer omits only what cannot be tracked
    in a public tree in the first place; everything else that is tracked is
    published. Each rule is stated once, here and in
    `docs/release/public-tree.md`."""

    def excluded(self, path):
        return PREPARE.public_tree_excluded("r5e-enterprise", path)

    def test_core_and_kernel_are_published_whole(self):
        for repo in ("r5e-core", "r5e-kernel"):
            self.assertIsNone(PREPARE.public_tree_excluded(repo, ".gitlab/ci/deploy.yml"))
            self.assertIsNone(PREPARE.public_tree_excluded(repo, ".release-forbidden"))

    def test_the_whole_omission_list_is_the_gate_patterns_and_the_private_ci(self):
        self.assertEqual(set(PREPARE.PUBLIC_TREE_OMITTED), {".release-forbidden", ".gitlab/"})
        for path in (".release-forbidden", ".gitlab/ci/private-deploy.yml", ".gitlab/anything-else.yml"):
            self.assertIsNotNone(self.excluded(path), path)

    def test_the_public_pipeline_is_published(self):
        # `.gitlab/` is a directory prefix; the gate set at the root is not under it.
        self.assertIsNone(self.excluded(".gitlab-ci.yml"))

    def test_build_output_is_omitted_defensively(self):
        for path in (
            "_build/dev/lib/app.beam",
            "deps/plug/mix.exs",
            "ui/node_modules/react/index.js",
            "native/cedar/target/release/libcedar.so",
        ):
            self.assertEqual(self.excluded(path), "build output", path)
        self.assertIsNone(self.excluded("apps/recurse_gateway/lib/target.ex"))
        self.assertIsNone(self.excluded("docs/deps.md"))

    def test_everything_else_tracked_is_published(self):
        for path in (
            "apps/recurse_fold/lib/recurse_fold.ex",
            "config/runtime.exs",
            "ui/design-tokens.json",
            "ui/src/lib/apiPaths.ts",
            "docs/release/oss-release-contract.md",
            "docs/release/public-tree.md",
            "specs/010-gateway-api-group/spec.md",
            "specs/012-compose-quickstart/plan.md",
            "specs/001-api-jido-foundations/contracts/openapi.yaml",
            "specs/009-llm-api-proxy/fixtures/cedar/eddy_smoke/bundle.cedar",
            "scripts/prepare-release.py",
            "scripts/prepare-ci-sources.py",
            "scripts/build-release.sh",
            "CONTRIBUTING.md",
            "CLA.md",
            "CLA-SIGNERS.md",
            "MAINTAINERS",
            "SECURITY.md",
            "CODE_OF_CONDUCT.md",
            "LICENSE.md",
            "THIRD_PARTY_NOTICES.md",
            "policy-starter/LICENSE",
            "AGENTS.md",
            "README.md",
            "Dockerfile",
            "docker-compose.yaml",
        ):
            self.assertIsNone(self.excluded(path), path)

    def test_the_page_names_every_omitted_path(self):
        for entry in PREPARE.PUBLIC_TREE_OMITTED:
            self.assertIn(f"`{entry}`", PUBLIC_TREE_PAGE, entry)


class TripwireTest(unittest.TestCase):
    """Paths that used to hold internal material left the tree. If one is
    tracked again the release stops and names it: the decision was that
    they leave the repository, not that a filter hides them."""

    def test_the_wire_is_the_agreed_list(self):
        self.assertEqual(
            set(PREPARE.INTERNAL_SHAPED),
            {"infra/", ".specify/", "design/", "docs/superpowers/", "HANDOFF.md", "r5e-PRD.md", "tmp/"},
        )

    def test_a_tracked_internal_shaped_path_is_refused_with_its_reason(self):
        for path, entry in (
            ("infra/helm/audit-console/values.yaml", "infra/"),
            ("infra/terraform/main.tf", "infra/"),
            (".specify/memory/constitution.md", ".specify/"),
            ("design/tokens.pen", "design/"),
            ("docs/superpowers/plans/2026-04-29-audit-pass-resolver-consolidation.md", "docs/superpowers/"),
            ("HANDOFF.md", "HANDOFF.md"),
            ("r5e-PRD.md", "r5e-PRD.md"),
            ("tmp/scratch.txt", "tmp/"),
        ):
            reason = PREPARE.refused(path)
            self.assertTrue(reason, path)
            self.assertIn(entry, reason)
            self.assertIs(PREPARE.release_forbidden(path), False, path)

    def test_a_lookalike_does_not_trip_it(self):
        for path in (
            "infrastructure-notes.md",
            "docs/superpowers-retired.md",
            "docs/release/HANDOFF-format.md",
            "apps/recurse_gateway/tmp/.gitkeep",
            "ui/design-tokens.json",
            "specs/012-compose-quickstart/plan.md",
        ):
            self.assertFalse(PREPARE.refused(path), path)

    def test_the_tripwire_is_not_an_omission(self):
        # A tripped path is refused, never quietly dropped.
        for entry in PREPARE.INTERNAL_SHAPED:
            path = entry + "x" if entry.endswith("/") else entry
            self.assertIsNone(PREPARE.public_tree_excluded("r5e-enterprise", path), path)

    def test_the_snapshotter_stops_and_names_the_path(self):
        entries = b"README.md\0file\0false\0infra/values.yaml\0file\0false\0"

        def jj(_repo, *args):
            if "log" in args:
                return b"a" * 40
            return entries

        with tempfile.TemporaryDirectory() as temp:
            with patch.object(SNAPSHOT, "jj", side_effect=jj):
                with self.assertRaisesRegex(ValueError, r"internal-shaped:\n  infra/values\.yaml: infra/ left the tree") as raised:
                    SNAPSHOT.snapshot(Path(temp), Path(temp) / "out.tgz", reject=PREPARE.refused)
            self.assertNotIn("README.md", str(raised.exception))
            self.assertFalse((Path(temp) / "out.tgz").exists())

    def test_the_snapshotter_archives_the_tracked_symlink_target(self):
        # `jj file show` prints nothing for a symlink; the target is read
        # from the Git backend, as prepare-ci-sources.py reads it. r5e-core
        # tracks symlinks in its conformance cases, so an empty target here
        # would extract to a different tree than the manifest hashes.
        entries = b"README.md\0file\0false\0bundle/log.jsonl\0symlink\0false\0"
        commit = "b" * 40
        calls = []

        def jj(_repo, *args):
            if "log" in args:
                return commit.encode()
            if args[-2:] == ("git", "root"):
                return b"/nowhere/.jj/repo/store/git\n"
            if "show" in args:
                return b"# readme\n"
            return entries

        def git(git_dir, *args):
            calls.append((git_dir, args))
            return b"../outside/log.jsonl"

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out.tgz"
            with patch.object(SNAPSHOT, "jj", side_effect=jj), patch.object(SNAPSHOT, "git", side_effect=git):
                self.assertEqual(SNAPSHOT.snapshot(Path(temp), output), commit)
            with tarfile.open(output, "r:gz") as archive:
                members = {member.name: member for member in archive.getmembers()}
                self.assertTrue(members["bundle/log.jsonl"].issym())
                self.assertEqual(members["bundle/log.jsonl"].linkname, "../outside/log.jsonl")
                self.assertEqual(archive.extractfile(members["README.md"]).read(), b"# readme\n")
        self.assertEqual(
            calls, [("/nowhere/.jj/repo/store/git", ("cat-file", "blob", f"{commit}:bundle/log.jsonl"))]
        )

    def test_the_page_names_every_wire(self):
        for entry in PREPARE.INTERNAL_SHAPED:
            self.assertIn(f"`{entry}`", PUBLIC_TREE_PAGE, entry)


class ForbiddenContentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def write(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, bytes):
            path.write_bytes(contents)
        else:
            path.write_text(contents)
        return path

    def test_patterns_come_from_a_file_that_is_not_published(self):
        self.assertIsNotNone(PREPARE.public_tree_excluded("r5e-enterprise", ".release-forbidden"))

    def test_no_file_means_no_patterns_rather_than_a_silent_pass(self):
        self.assertEqual(PREPARE.forbidden_patterns(self.root), [])

    def test_comments_and_blank_lines_are_not_patterns(self):
        self.write(".release-forbidden", "# a comment\n\n  \nsecret\\.example  # the reason\n")
        patterns = PREPARE.forbidden_patterns(self.root)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0][1], "the reason")

    def test_a_hit_is_reported_with_its_path_line_and_reason(self):
        self.write(".release-forbidden", "999988887777  # an account id\n")
        patterns = PREPARE.forbidden_patterns(self.root)

        context = self.root / "context"
        self.write("context/clean.md", "nothing to see\n")
        self.write("context/deploy/values.yaml", "first\nregistry: 999988887777.example\nlast\n")

        findings = PREPARE.content_forbidden(context, patterns)
        self.assertEqual(findings, ["deploy/values.yaml:2: an account id"])

    def test_a_clean_tree_reports_nothing(self):
        self.write(".release-forbidden", "999988887777\n")
        patterns = PREPARE.forbidden_patterns(self.root)
        context = self.root / "context"
        self.write("context/clean.md", "nothing to see\n")
        self.assertEqual(PREPARE.content_forbidden(context, patterns), [])

    def test_binary_files_are_searched_too(self):
        self.write(".release-forbidden", "999988887777\n")
        patterns = PREPARE.forbidden_patterns(self.root)
        context = self.root / "context"
        self.write("context/image.bin", b"\x00\x01999988887777\xff")
        self.assertEqual(len(PREPARE.content_forbidden(context, patterns)), 1)


class ReleaseForbiddenTest(unittest.TestCase):
    """`release_forbidden` refuses rather than omits: a tracked path that
    looks like runtime state or a private key stops the release."""

    def test_runtime_state_and_keys_are_refused(self):
        for path in (
            ".r5e/keys/node_ed25519.key",
            "apps/recurse_fold/.r5e-fold/chain",
            ".jj/repo",
            "secrets/token",
            ".env",
            ".env.production",
            "infra/deploy.pem",
        ):
            self.assertTrue(PREPARE.release_forbidden(path), path)
            self.assertEqual(PREPARE.refused(path), "runtime state or a secret-shaped file")

    def test_ordinary_source_is_not(self):
        for path in ("lib/app.ex", ".env.example", "docs/guide.md", ".release-forbidden"):
            self.assertFalse(PREPARE.release_forbidden(path), path)
            self.assertFalse(PREPARE.refused(path), path)


if __name__ == "__main__":
    unittest.main()
