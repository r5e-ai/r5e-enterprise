import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ENTERPRISE = Path(__file__).resolve().parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "prepare_ci_sources", ENTERPRISE / "scripts" / "prepare-ci-sources.py"
)
PREPARE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(PREPARE)


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()


def repository(root, name, files):
    repo = root / name
    repo.mkdir()
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    git(repo, "config", "user.name", "CI test")
    git(repo, "config", "user.email", "ci-test@example.invalid")
    for path, contents in files.items():
        destination = repo / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(contents)
    git(repo, "add", ".")
    git(repo, "commit", "--quiet", "-m", "fixture")
    return repo, git(repo, "rev-parse", "HEAD")


class PrepareCiSourcesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        safety = """\
from pathlib import Path
def release_forbidden(path):
    parts = Path(path).parts
    return "secrets" in parts or any(part == ".r5e" or part.startswith((".r5e.", ".r5e-")) for part in parts) or Path(path).suffix == ".pem"
"""
        required = {
            "scripts/prepare-release.py": safety,
            "docker-compose/fold-context.dockerignore": "*\n!r5e-enterprise\n!r5e-kernel\n!r5e-core\n!repos.lock.json\n",
            "mix.exs": "# enterprise\n",
        }
        self.enterprise, self.enterprise_commit = repository(
            self.root, "enterprise", required
        )

    def tearDown(self):
        self.temporary.cleanup()

    def write_lock(self, core_commit, kernel_commit):
        lock = self.root / "release-dependencies.json"
        lock.write_text(
            json.dumps(
                {
                    "format": "r5e-release-dependencies/v1",
                    "repositories": {
                        "r5e-core": {"url": "https://example.invalid/core.git", "commit": core_commit},
                        "r5e-kernel": {"url": "https://example.invalid/kernel.git", "commit": kernel_commit},
                    },
                }
            )
        )
        return lock

    def test_missing_pinned_commit_is_rejected(self):
        core, core_commit = repository(self.root, "core", {"README.md": "core\n"})
        kernel, kernel_commit = repository(self.root, "kernel", {"mix.exs": "# kernel\n"})
        lock = self.write_lock("0" * 40, kernel_commit)

        with self.assertRaisesRegex(ValueError, "does not contain pinned commit"):
            PREPARE.prepare_context(
                enterprise=self.enterprise,
                enterprise_commit=self.enterprise_commit,
                pin_file=lock,
                output=self.root / "output",
                overrides={"r5e-core": core, "r5e-kernel": kernel},
            )

    def test_tracked_secret_is_rejected(self):
        core, core_commit = repository(
            self.root, "core-secret", {"secrets/node.pem": "private\n"}
        )
        kernel, kernel_commit = repository(
            self.root, "kernel-clean", {"mix.exs": "# kernel\n"}
        )
        lock = self.write_lock(core_commit, kernel_commit)

        with self.assertRaisesRegex(ValueError, "runtime state, secrets or internal-shaped"):
            PREPARE.prepare_context(
                enterprise=self.enterprise,
                enterprise_commit=self.enterprise_commit,
                pin_file=lock,
                output=self.root / "output",
                overrides={"r5e-core": core, "r5e-kernel": kernel},
            )


if __name__ == "__main__":
    unittest.main()
