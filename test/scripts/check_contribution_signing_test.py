# SPDX-License-Identifier: AGPL-3.0-only
"""`scripts/check-contribution-signing.sh`, run against a fixture repository.

The check is the first gate of every merge request, so what it accepts and
refuses is pinned here rather than discovered by a contributor whose branch it
rejects for the wrong reason.
"""

import os
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest


ENTERPRISE = Path(__file__).resolve().parents[2]
CHECK = ENTERPRISE / "scripts" / "check-contribution-signing.sh"
CLA = ENTERPRISE / "CLA.md"

AUTHOR = "contributor@example.com"
ACCOUNT = "gitlab.com/example-contributor"


def git(repo, *arguments):
    subprocess.run(
        ["git", "-c", "user.name=Example", f"-c", f"user.email={AUTHOR}", *arguments],
        cwd=repo, check=True, capture_output=True, text=True,
    )


class ContributionSigningTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        git(self.repo, "init", "-q", "-b", "main", ".")
        (self.repo / "CLA.md").write_bytes(CLA.read_bytes())
        (self.repo / "CLA-SIGNERS.md").write_text("# Contributors who have agreed to CLA.md\n")
        (self.repo / "MAINTAINERS").write_text("gitlab.com/r5e-tjones\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.repo, capture_output=True, text=True, check=True
        ).stdout.strip()
        self.digest = hashlib.sha256((self.repo / "CLA.md").read_bytes()).hexdigest()

    def commit(self, message):
        path = self.repo / "change.txt"
        path.write_text(message)
        git(self.repo, "add", "change.txt")
        git(self.repo, "commit", "-q", "-m", message)

    def sign(self, account, version="v1.0", digest=None):
        line = (
            f"{account} {version} cla:sha256:{digest or self.digest} 2026-09-05 "
            "countersigned-by:gitlab.com/r5e-tjones\n"
        )
        with (self.repo / "CLA-SIGNERS.md").open("a") as signers:
            signers.write(line)

    def run_check(self, author="", require_cla="0"):
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("CI_", "GITLAB_"))
        }
        environment["R5E_REQUIRE_CLA"] = require_cla
        return subprocess.run(
            [str(CHECK), self.base, author],
            cwd=self.repo, env=environment, capture_output=True, text=True,
        )

    # --- DCO ---------------------------------------------------------------

    def test_a_commit_without_a_signoff_fails_and_names_the_fix(self):
        self.commit("no signoff")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("DCO:", result.stdout)
        self.assertIn("git commit --amend --no-edit -s", result.stdout)

    def test_a_signed_off_commit_passes(self):
        self.commit(f"signed\n\nSigned-off-by: Example <{AUTHOR}>")
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("contribution signing: ok", result.stdout)

    def test_a_signoff_for_a_different_author_does_not_count(self):
        self.commit("signed by someone else\n\nSigned-off-by: Other <other@example.com>")
        self.assertEqual(self.run_check().returncode, 1)

    # --- CLA ---------------------------------------------------------------

    def test_the_cla_is_only_required_when_asked_for(self):
        self.commit(f"signed\n\nSigned-off-by: Example <{AUTHOR}>")
        self.assertEqual(self.run_check(author=ACCOUNT, require_cla="0").returncode, 0)

    def test_an_unsigned_account_fails_with_the_current_digest(self):
        self.commit(f"signed\n\nSigned-off-by: Example <{AUTHOR}>")
        result = self.run_check(author=ACCOUNT, require_cla="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("CLA:", result.stdout)
        self.assertIn(self.digest, result.stdout)

    def test_a_signed_account_passes(self):
        self.sign(ACCOUNT)
        self.commit(f"signed\n\nSigned-off-by: Example <{AUTHOR}>")
        self.assertEqual(self.run_check(author=ACCOUNT, require_cla="1").returncode, 0)

    def test_a_signature_against_an_older_cla_text_does_not_count(self):
        self.sign(ACCOUNT, digest="0" * 64)
        self.commit(f"signed\n\nSigned-off-by: Example <{AUTHOR}>")
        self.assertEqual(self.run_check(author=ACCOUNT, require_cla="1").returncode, 1)

    def test_a_maintainer_does_not_need_a_cla_line(self):
        self.commit(f"signed\n\nSigned-off-by: Example <{AUTHOR}>")
        self.assertEqual(
            self.run_check(author="gitlab.com/r5e-tjones", require_cla="1").returncode, 0
        )

    def test_the_shipped_signers_file_agrees_with_the_shipped_cla(self):
        digest = hashlib.sha256((ENTERPRISE / "CLA.md").read_bytes()).hexdigest()
        self.assertIn(f"cla:sha256:{digest}", (ENTERPRISE / "CLA-SIGNERS.md").read_text())


if __name__ == "__main__":
    unittest.main()
