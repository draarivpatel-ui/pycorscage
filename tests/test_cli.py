"""CLI evaluation, lint, file-safety, exit-code, and ANSI-neutralization tests."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pycorscage.cli import ConfigReadError, MAX_CONFIG_BYTES, neutralize_text, read_config_file

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

    def test_argparse_error_neutralizes_terminal_controls(self):
        hostile = "bad\x1b[31m\u202e\u2028\n[critical] forged"
        result = self.cli("lint", "--config", str(self.config), hostile)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(b"\x1b", result.stderr)
        self.assertNotIn("\u202e".encode("utf-8"), result.stderr)
        self.assertNotIn("\u2028".encode("utf-8"), result.stderr)
        self.assertNotIn(b"\n[critical]", result.stderr)


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

    def test_nonstandard_json_constants_exit_two(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                self.config.write_text('{"max_age": ' + constant + '}', encoding="utf-8")
                result = self.cli("lint", "--config", str(self.config))
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"not valid strict JSON", result.stderr)

    def test_deeply_nested_json_exit_two_without_traceback(self):
        depth = 20000
        self.config.write_text("[" * depth + "]" * depth, encoding="utf-8")
        result = self.cli("lint", "--config", str(self.config))
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"nesting cap", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_json_nesting_cap_boundaries(self):
        valid_depth = 127
        self.config.write_text('{"unknown":' + "[" * valid_depth + "0" + "]" * valid_depth + "}", encoding="utf-8")
        loaded = read_config_file(str(self.config))
        self.assertIn("unknown", loaded)
        invalid_depth = 128
        self.config.write_text('{"unknown":' + "[" * invalid_depth + "0" + "]" * invalid_depth + "}", encoding="utf-8")
        with self.assertRaises(ConfigReadError):
            read_config_file(str(self.config))

    def test_json_nesting_scanner_ignores_brackets_in_strings(self):
        self.config.write_text('{"unknown":"' + "[" * 200 + '"}', encoding="utf-8")
        loaded = read_config_file(str(self.config))
        self.assertEqual(len(loaded["unknown"]), 200)

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

    def test_symlink_rejected_without_nofollow_open_flag(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW is already absent")
        target = self.dir / "target.json"
        target.write_text(json.dumps(CLEAN_CONFIG), encoding="utf-8")
        link = self.dir / "link-no-follow.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        saved = os.O_NOFOLLOW
        del os.O_NOFOLLOW
        try:
            with self.assertRaises(ConfigReadError):
                read_config_file(str(link))
        finally:
            os.O_NOFOLLOW = saved

    def test_embedded_nul_config_path_raises_config_error(self):
        with self.assertRaises(ConfigReadError):
            read_config_file("bad\x00path")

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
    "line\nforge\ttab",
    "bidi\u202eoverride",
]


class TestAnsiNeutralizerSpecific(unittest.TestCase):
    def test_newline_and_tab_cannot_forge_output_lines(self):
        self.assertEqual(neutralize_text("good\n[critical] forged\tline"), "good?[critical] forged?line")

    def test_bidi_controls_are_replaced(self):
        self.assertEqual(neutralize_text("bidi\u202eoverride"), "bidi?override")

    def test_unicode_line_separators_are_replaced(self):
        self.assertEqual(neutralize_text("one\u2028two\u2029three"), "one?two?three")


class TestCliHelpSnapshots(unittest.TestCase):
    _OPTIONS_HEADER_RE = re.compile(r"\b(?:options|optional arguments):")

    def _run_help(self, *args):
        result = run_cli(list(args) + ["--help"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        return " ".join(result.stdout.decode("utf-8").split())

    def _assert_ordered_fragments(self, text, fragments):
        cursor = 0
        for fragment in fragments:
            index = text.find(fragment, cursor)
            self.assertNotEqual(
                index,
                -1,
                "expected fragment %r after offset %d in %r" % (fragment, cursor, text),
            )
            cursor = index + len(fragment)

    def _options_section(self, normalized):
        match = self._OPTIONS_HEADER_RE.search(normalized)
        self.assertIsNotNone(match, "missing options section header in %r" % (normalized,))
        return normalized[match.end():]

    def test_top_level_help_sections_and_subcommands(self):
        normalized = self._run_help()
        self._assert_ordered_fragments(
            normalized,
            [
                "usage: pycorscage [-h] {check,lint} ...",
                "Audit strict CORS policy JSON and evaluate browser CORS requests.",
                "positional arguments:",
                "{check,lint}",
                "check evaluate one request against a policy",
                "lint audit a policy configuration",
            ],
        )
        options_text = self._options_section(normalized)
        self.assertIn("-h, --help", options_text)
        self.assertGreater(
            normalized.find(options_text),
            normalized.find("positional arguments:"),
        )

    def test_check_help_sections_and_safety_options(self):
        normalized = self._run_help("check")
        self._assert_ordered_fragments(
            normalized,
            [
                "usage: pycorscage check",
                "--config CONFIG",
                "--origin ORIGIN",
                "--method METHOD",
                "--request-headers REQUEST_HEADERS",
                "--preflight",
                "--private-network",
                "--json",
            ],
        )
        options_text = self._options_section(normalized)
        self._assert_ordered_fragments(
            options_text,
            [
                "-h, --help",
                "--config CONFIG path to a strict JSON policy file",
                "--origin ORIGIN Origin header value to evaluate",
                "--method METHOD request method, or Access-Control-Request-Method with --preflight",
                "--request-headers REQUEST_HEADERS comma-separated Access-Control-Request-Headers value",
                "--preflight evaluate as an OPTIONS CORS preflight",
                "--private-network send Access-Control-Request-Private-Network: true",
                "--json emit machine-readable JSON",
            ],
        )

    def test_lint_help_sections_and_options(self):
        normalized = self._run_help("lint")
        self._assert_ordered_fragments(
            normalized,
            [
                "usage: pycorscage lint",
                "--config CONFIG",
                "--json",
            ],
        )
        options_text = self._options_section(normalized)
        self._assert_ordered_fragments(
            options_text,
            [
                "-h, --help",
                "--config CONFIG path to a strict JSON policy file",
                "--json emit machine-readable JSON",
            ],
        )
        for check_only_flag in (
            "--origin",
            "--method",
            "--request-headers",
            "--preflight",
            "--private-network",
        ):
            self.assertNotIn(check_only_flag, normalized)


add_matrix_tests(TestAnsiNeutralizer, "ansi", ANSI_CASES, TestAnsiNeutralizer.check_neutralized)


if __name__ == "__main__":
    unittest.main()
