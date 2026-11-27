"""CLI evaluation, lint, file-safety, exit-code, and ANSI-neutralization tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pycorscage.cli import MAX_CONFIG_BYTES, neutralize_text, read_config_file

from _support import add_matrix_tests

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

CLEAN_CONFIG = {
    "allowed_origins": ["https://app.example.com"],
    "allowed_methods": ["GET", "POST"],
    "allowed_headers": ["content-type"],
    "max_age": 60,
}


def run_cli(args):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    return subprocess.run(
        [sys.executable, "-m", "pycorscage"] + list(args),
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CliCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.config = self.dir / "policy.json"
        self.config.write_text(json.dumps(CLEAN_CONFIG), encoding="utf-8")

    def cli(self, *args):
        return run_cli(args)


class TestCliCore(CliCase):
    def test_check_allowed_json_exit_zero(self):
        result = self.cli("check", "--config", str(self.config), "--origin", "https://app.example.com", "--method", "GET", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertTrue(data["allowed"])
        self.assertEqual(data["headers"]["Access-Control-Allow-Origin"], "https://app.example.com")
        self.assertEqual(data["status_code"], None)

    def test_check_denied_json_exit_one(self):
        result = self.cli("check", "--config", str(self.config), "--origin", "https://evil.example", "--json")
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertFalse(data["allowed"])
        self.assertEqual(data["code"], "CORS_ORIGIN_NOT_ALLOWED")

    def test_check_preflight_allowed(self):
        result = self.cli(
            "check",
            "--config", str(self.config),
            "--origin", "https://app.example.com",
            "--method", "POST",
            "--request-headers", "content-type",
            "--preflight",
            "--json",
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertTrue(data["is_preflight"])
        self.assertEqual(data["status_code"], 204)
        self.assertEqual(data["headers"]["Access-Control-Allow-Methods"], "POST")

    def test_check_preflight_denied_method(self):
        result = self.cli(
            "check",
            "--config", str(self.config),
            "--origin", "https://app.example.com",
            "--method", "TRACE",
            "--preflight",
            "--json",
        )
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(data["status_code"], 403)

    def test_check_private_network_flag(self):
        config = dict(CLEAN_CONFIG)
        config["allow_private_network"] = True
        self.config.write_text(json.dumps(config), encoding="utf-8")
        result = self.cli(
            "check", "--config", str(self.config), "--origin", "https://app.example.com",
            "--method", "POST", "--preflight", "--private-network", "--json"
        )
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(data["headers"]["Access-Control-Allow-Private-Network"], "true")

    def test_check_human_output(self):
        result = self.cli("check", "--config", str(self.config), "--origin", "https://app.example.com")
        self.assertEqual(result.returncode, 0)
        text = result.stdout.decode("utf-8")
        self.assertIn("allowed: yes", text)
        self.assertIn("code: CORS_ORIGIN_ALLOWED", text)

    def test_lint_clean_exit_zero(self):
        result = self.cli("lint", "--config", str(self.config), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout.decode("utf-8"))["findings"], [])

    def test_lint_finding_exit_one(self):
        config = dict(CLEAN_CONFIG)
        config["allowed_origins"] = ["*"]
        config["allow_credentials"] = True
        self.config.write_text(json.dumps(config), encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config), "--json")
        self.assertEqual(result.returncode, 1)
        findings = json.loads(result.stdout.decode("utf-8"))["findings"]
        self.assertIn("CORS_WILDCARD_WITH_CREDENTIALS", {finding["code"] for finding in findings})

    def test_lint_human_output(self):
        config = dict(CLEAN_CONFIG)
        config["max_age"] = -1
        self.config.write_text(json.dumps(config), encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertEqual(result.returncode, 1)
        self.assertIn("CORS_INVALID_MAX_AGE", result.stdout.decode("utf-8"))

    def test_invalid_policy_for_check_exit_two(self):
        config = dict(CLEAN_CONFIG)
        config["allow_credentials"] = True
        config["allowed_origins"] = ["*"]
        self.config.write_text(json.dumps(config), encoding="utf-8")
        result = self.cli("check", "--config", str(self.config), "--origin", "https://app.example.com")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"CORS_WILDCARD_WITH_CREDENTIALS", result.stderr)

    def test_help_exit_zero(self):
        result = self.cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"check", result.stdout)

    def test_no_subcommand_exit_two(self):
        result = self.cli()
        self.assertEqual(result.returncode, 2)

    def test_unknown_argument_exit_two(self):
        result = self.cli("lint", "--config", str(self.config), "--not-a-real-option")
        self.assertEqual(result.returncode, 2)


class TestCliFileSafety(CliCase):
    def test_missing_file_exit_two(self):
        result = self.cli("lint", "--config", str(self.dir / "missing.json"))
        self.assertEqual(result.returncode, 2)

    def test_invalid_json_exit_two(self):
        self.config.write_text("{not json", encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertEqual(result.returncode, 2)

    def test_top_level_array_exit_two(self):
        self.config.write_text("[]", encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertEqual(result.returncode, 2)

    def test_duplicate_json_key_exit_two(self):
        self.config.write_text('{"allowed_origins":[],"allowed_origins":[]}', encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertEqual(result.returncode, 2)

    def test_directory_rejected(self):
        result = self.cli("lint", "--config", str(self.dir))
        self.assertEqual(result.returncode, 2)

    def test_device_rejected(self):
        result = self.cli("lint", "--config", "/dev/null")
        self.assertEqual(result.returncode, 2)

    def test_symlink_rejected(self):
        target = self.dir / "target.json"
        target.write_text(json.dumps(CLEAN_CONFIG), encoding="utf-8")
        link = self.dir / "link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        result = self.cli("lint", "--config", str(link))
        self.assertEqual(result.returncode, 2)

    def test_fifo_rejected(self):
        fifo = self.dir / "policy.fifo"
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo unavailable")
        try:
            os.mkfifo(str(fifo))
        except OSError:
            self.skipTest("fifo creation unavailable")
        result = self.cli("lint", "--config", str(fifo))
        self.assertEqual(result.returncode, 2)

    def test_oversized_file_rejected(self):
        oversized = self.dir / "large.json"
        with oversized.open("wb") as handle:
            handle.write(b" " * (MAX_CONFIG_BYTES + 1))
        result = self.cli("lint", "--config", str(oversized))
        self.assertEqual(result.returncode, 2)

    def test_invalid_utf8_rejected(self):
        self.config.write_bytes(b"\xff\xfe\xfa")
        result = self.cli("lint", "--config", str(self.config))
        self.assertEqual(result.returncode, 2)

    def test_read_config_file_returns_mapping(self):
        loaded = read_config_file(str(self.config))
        self.assertEqual(loaded["allowed_origins"], ["https://app.example.com"])

    def test_ansi_escape_in_unknown_key_neutralized(self):
        evil_key = "bad\x1b[31m_key"
        self.config.write_text(json.dumps({evil_key: True}), encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertNotIn(b"\x1b", result.stdout)
        self.assertNotIn(b"\x1b", result.stderr)

    def test_control_characters_in_unknown_key_neutralized(self):
        evil_key = "bad\x00\x07_key"
        self.config.write_text(json.dumps({evil_key: True}), encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertNotIn(b"\x00", result.stdout)
        self.assertNotIn(b"\x07", result.stdout)


class TestAnsiNeutralizer(unittest.TestCase):
    def check_neutralized(self, case):
        self.assertNotIn("\x1b", neutralize_text(case))
        for char in neutralize_text(case):
            if char not in ("\n", "\t"):
                self.assertGreaterEqual(ord(char), 32)
                self.assertNotEqual(ord(char), 127)


ANSI_CASES = [
    "\x1b[31mred\x1b[0m",
    "\x1b[1;42minverse",
    "\x1b]0;window title\x07text",
    "\x1b]8;;https://evil.example\x1b\\link",
    "plain\x1bescaped",
    "nul\x00bell\x07delete\x7f",
    "\x1b[2J\x1b[Hhome",
    "\x9b31mnot-csi-safe",
]


add_matrix_tests(TestAnsiNeutralizer, "ansi", ANSI_CASES, TestAnsiNeutralizer.check_neutralized)


if __name__ == "__main__":
    unittest.main()
