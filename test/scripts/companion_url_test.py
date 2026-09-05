import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
prepare = __import__("prepare-ci-sources")


class CompanionUrlTest(unittest.TestCase):
    URL = "https://gitlab.com/r5e-group/r5e-kernel.git"

    def test_default_is_the_pinned_url(self):
        os.environ.pop("R5E_COMPANION_GIT_BASE", None)
        self.assertEqual(prepare.companion_url(self.URL), self.URL)

    def test_base_rewrites_only_the_location(self):
        os.environ["R5E_COMPANION_GIT_BASE"] = "https://gitlab.com/r5e-group/staging/"
        try:
            self.assertEqual(
                prepare.companion_url(self.URL),
                "https://gitlab.com/r5e-group/staging/r5e-kernel.git",
            )
        finally:
            os.environ.pop("R5E_COMPANION_GIT_BASE", None)


if __name__ == "__main__":
    unittest.main()
