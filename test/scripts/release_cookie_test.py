#!/usr/bin/env python3
"""Exercise the release env hook without booting enterprise or touching Docker."""
import concurrent.futures
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "rel/env.sh.eex"


class ReleaseCookieTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="r5e-cookie-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cookie = self.root / "secrets with spaces" / "erlang.cookie"

    def run_hook(self, command="start", path=None, override=None, extra=None):
        env = os.environ.copy()
        env.pop("RELEASE_COOKIE", None)
        env.update(RELEASE_ROOT=str(self.root), RELEASE_COMMAND=command,
                   R5E_RELEASE_COOKIE_PATH=str(path or self.cookie), HOOK=str(HOOK))
        if override is not None:
            env["RELEASE_COOKIE"] = override
        if extra:
            env.update(extra)
        # Hash only: neither assertions nor captured diagnostics reveal cookies.
        return subprocess.run(["sh", "-c", '. "$HOOK"; printf %s "$RELEASE_COOKIE" | openssl dgst -sha256'],
                              env=env, text=True, capture_output=True)

    def test_first_boot_persistence_and_direct_rpc(self):
        first = self.run_hook("eval")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(self.cookie.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.run_hook().stdout, first.stdout)
        self.assertEqual(self.run_hook("rpc").stdout, first.stdout)
        self.assertEqual(list(self.cookie.parent.glob(".erlang.cookie.*")), [])

    def test_separate_deployments_have_different_cookies(self):
        first = self.run_hook()
        second = self.run_hook(path=self.root / "other" / "erlang.cookie")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(first.stdout, second.stdout)

    def test_parallel_initialization_publishes_one_complete_cookie(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.run_hook(), range(16)))
        self.assertTrue(all(r.returncode == 0 for r in results))
        self.assertEqual(len({r.stdout for r in results}), 1)
        self.assertEqual(list(self.cookie.parent.glob(".erlang.cookie.*")), [])

    def test_override_does_not_create_or_overwrite_cookie(self):
        result = self.run_hook("rpc", override="test-only-explicit-override")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.cookie.exists())
        self.assertNotIn("test-only-explicit-override", result.stdout + result.stderr)
        self.run_hook()
        before = hashlib.sha256(self.cookie.read_bytes()).digest()
        self.assertEqual(self.run_hook(override="another-test-override").returncode, 0)
        self.assertEqual(hashlib.sha256(self.cookie.read_bytes()).digest(), before)
        self.assertNotEqual(self.run_hook(override="").returncode, 0)

    def test_control_commands_refuse_missing_cookie_without_creating_it(self):
        for command in ("rpc", "remote", "restart", "stop", "pid"):
            with self.subTest(command=command):
                result = self.run_hook(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("refusing control command", result.stderr)
                self.assertFalse(self.cookie.exists())

    def test_wrong_cookie_directory_cannot_silently_regenerate_for_rpc(self):
        self.run_hook()
        wrong = self.root / "wrong" / "erlang.cookie"
        self.assertNotEqual(self.run_hook("rpc", path=wrong).returncode, 0)
        self.assertFalse(wrong.exists())

    def test_corrupt_cookie_and_permissions_refuse_without_replacement(self):
        self.run_hook()
        self.cookie.write_text("invalid-test-data\n")
        before = self.cookie.read_bytes()
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertEqual(self.cookie.read_bytes(), before)
        self.cookie.write_text("a" * 64 + "\n")
        self.cookie.chmod(0o644)
        self.assertNotEqual(self.run_hook().returncode, 0)

    def test_symlink_and_non_directory_paths_refuse(self):
        target = self.root / "target"
        target.write_text("a" * 64 + "\n")
        self.cookie.parent.mkdir()
        self.cookie.symlink_to(target)
        self.assertNotEqual(self.run_hook().returncode, 0)
        self.assertEqual(target.read_text(), "a" * 64 + "\n")
        self.assertNotEqual(self.run_hook(path=target / "cookie").returncode, 0)

    def test_version_and_unknown_commands_do_not_create_state(self):
        for command in ("version", "", "not-a-command"):
            self.assertEqual(self.run_hook(command).returncode, 0)
            self.assertFalse(self.cookie.exists())

    def test_relative_paths_refuse(self):
        self.assertNotEqual(self.run_hook(path=Path("relative-cookie")).returncode, 0)

    def test_both_image_builds_include_runtime_template(self):
        for name in ("Dockerfile", "docker-compose/Dockerfile.fold"):
            with self.subTest(name=name):
                self.assertTrue("COPY r5e-enterprise/rel ./rel" in (ROOT / name).read_text(),
                                f"{name} must copy the release env template")


if __name__ == "__main__":
    unittest.main()
