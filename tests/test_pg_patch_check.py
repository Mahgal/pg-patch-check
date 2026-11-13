"""Tests for pg_patch_check.py (stdlib only)."""

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pg_patch_check as pg  # noqa: E402


def run(*args):
    return subprocess.run(
        [sys.executable, "pg_patch_check.py", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


class TestParse(unittest.TestCase):
    def test_full_version_string(self):
        self.assertEqual(pg.parse_version(
            "PostgreSQL 16.14 on x86_64-pc-linux-gnu"), (16, 14))

    def test_bare_version(self):
        self.assertEqual(pg.parse_version("17.12"), (17, 12))

    def test_unparseable_raises(self):
        with self.assertRaises(ValueError):
            pg.parse_version("not a version")


class TestCheck(unittest.TestCase):
    def test_6471_vulnerable(self):
        r = pg.check((16, 14))
        self.assertFalse(r["ok"])
        self.assertTrue(any("6471" in f["id"] for f in r["findings"]))

    def test_6471_fixed_but_nov12_pending(self):
        r = pg.check((16, 15))
        self.assertFalse(r["ok"])  # 16.16 required for the Nov 12 batch
        self.assertFalse(any("6471" in f["id"] for f in r["findings"]))

    def test_fully_patched(self):
        self.assertTrue(pg.check((17, 12))["ok"])
        self.assertTrue(pg.check((18, 7))["ok"])

    def test_pg14_eol_warning_but_patched(self):
        r = pg.check((14, 25))
        self.assertTrue(r["ok"])
        self.assertTrue(any(f["id"] == "eol" for f in r["findings"]))

    def test_unsupported_major(self):
        r = pg.check((13, 20))
        self.assertFalse(r["ok"])
        self.assertEqual(r["findings"][0]["id"], "unsupported")


class TestCli(unittest.TestCase):
    def test_cli_vulnerable_exit_1(self):
        result = run("--version-string", "PostgreSQL 15.18 on Debian")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Vulnerable", result.stdout)

    def test_cli_patched_exit_0(self):
        result = run("--version-string", "18.7")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("OK", result.stdout)

    def test_cli_json(self):
        result = run("--version-string", "16.14", "--format", "json")
        self.assertEqual(result.returncode, 1)
        import json
        data = json.loads(result.stdout)
        self.assertEqual(data["version"], "16.14")
        self.assertFalse(data["ok"])


if __name__ == "__main__":
    unittest.main()
