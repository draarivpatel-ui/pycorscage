"""Repository, metadata, documentation, and hygiene invariant tests."""

from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".txt", ".in"}


def repo_files():
    output = []
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError:
        result = None
    if result is not None and result.returncode == 0:
        for encoded in result.stdout.split(b"\x00"):
            if not encoded:
                continue
            path = ROOT / os.fsdecode(encoded)
            if path.suffix in TEXT_SUFFIXES or path.name in {"LICENSE", ".gitignore", "MANIFEST.in"}:
                output.append(path)
        return output

    for base, dirs, files in os.walk(str(ROOT)):
        dirs[:] = [item for item in dirs if item not in {".git", "__pycache__", "dist", "build", ".venv"}]
        for name in files:
            if name.endswith((".pyc", ".pyo")) or name == ".DS_Store":
                continue
            path = Path(base) / name
            if path.suffix in TEXT_SUFFIXES or name in {"LICENSE", ".gitignore", "MANIFEST.in"}:
                output.append(path)
    return output


def read_bytes(path):
    return path.read_bytes()


class TestRepositoryHygiene(unittest.TestCase):
    def test_no_em_dashes_in_repository_text(self):
        needle = b"\xe2\x80\x94"
        offenders = [str(path) for path in repo_files() if needle in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_no_en_dashes_in_repository_text(self):
        needle = b"\xe2\x80\x93"
        offenders = [str(path) for path in repo_files() if needle in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_no_crlf_in_repository_text(self):
        offenders = [str(path) for path in repo_files() if b"\r\n" in read_bytes(path) or b"\r" in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_no_local_home_paths_in_repository_text(self):
        needle = ("/" + "Users/").encode("utf-8")
        offenders = [str(path) for path in repo_files() if needle in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_no_private_email_markers_in_repository_text(self):
        markers = [
            ("someone" + "@" + "gmail.com").encode("utf-8"),
            ("handle-redacted286" + "@" + "gmail.com").encode("utf-8"),
        ]
        offenders = []
        for path in repo_files():
            data = read_bytes(path)
            if any(marker in data for marker in markers):
                offenders.append(str(path))
        self.assertEqual(offenders, [])

    def test_no_commit_trailer_marker_in_repository_text(self):
        marker = ("Co" + "-Authored" + "-By:").encode("utf-8")
        offenders = [str(path) for path in repo_files() if marker in read_bytes(path)]
        self.assertEqual(offenders, [])

    def test_gitignore_covers_bytecode_and_build_output(self):
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for token in ("__pycache__/", "*.py[cod]", "dist/", "build/"):
            self.assertIn(token, text)


class TestProjectMetadata(unittest.TestCase):
    def setUp(self):
        self.pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    def test_pep621_identity(self):
        self.assertIn('name = "pycorscage"', self.pyproject)
        self.assertIn('version = "1.0.0"', self.pyproject)
        self.assertIn('license = "MIT"', self.pyproject)

    def test_python_floor_and_zero_dependencies(self):
        self.assertIn('requires-python = ">=3.9"', self.pyproject)
        self.assertIn('dependencies = []', self.pyproject)

    def test_src_layout_and_py_typed_config(self):
        self.assertIn('package-dir = { "" = "src" }', self.pyproject)
        self.assertIn('pycorscage = ["py.typed"]', self.pyproject)
        self.assertTrue((ROOT / "src" / "pycorscage" / "py.typed").exists())

    def test_cli_entry_point(self):
        self.assertIn('pycorscage = "pycorscage.cli:main"', self.pyproject)

    def test_project_urls(self):
        self.assertIn('https://github.com/draarivpatel-ui/pycorscage', self.pyproject)
        private_marker = "someone" + "@" + "gmail.com"
        self.assertNotIn(private_marker, self.pyproject)

    def test_python_39_compatible_constructs(self):
        offenders = []
        for path in (ROOT / "src").rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"^\s*match\s+", text, re.MULTILINE) and re.search(r"^\s*case\s+", text, re.MULTILINE):
                offenders.append(str(path))
            if "tomllib" in text:
                offenders.append(str(path))
        self.assertEqual(offenders, [])


class TestDocsAndWorkflows(unittest.TestCase):
    def test_license_is_mit(self):
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("MIT License", text)
        self.assertIn("Permission is hereby granted", text)

    def test_security_policy_exists(self):
        text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("Reporting a vulnerability", text)
        self.assertIn("Scope", text)

    def test_readme_threat_model_and_examples(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        for token in ("Threat model", "WSGI middleware", "ASGI middleware", "CLI auditor", "Lint finding codes"):
            self.assertIn(token, text)

    def test_readme_has_honest_pypi_pending_note(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("not claimed to be published on PyPI yet", text)

    def test_good_first_issues_has_ten_specs(self):
        text = (ROOT / "docs" / "GOOD_FIRST_ISSUES.md").read_text(encoding="utf-8")
        count = sum(1 for line in text.splitlines() if line.startswith("## ") and line != "## ")
        self.assertEqual(count, 10)

    def test_ci_matrix_and_commands(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for token in ("ubuntu-24.04", '"3.9"', '"3.10"', '"3.11"', '"3.12"', '"3.13"', "unittest discover", "python3 -m build", "check_dist.py"):
            self.assertIn(token, text)

    def test_publish_uses_oidc_not_token(self):
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("id-token: write", text)
        self.assertIn("environment:", text)
        self.assertIn("name: pypi", text)
        self.assertIn("pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086", text)
        self.assertNotIn("PYPI_TOKEN", text)
        self.assertNotIn("password:", text)

    def test_issue_templates_exist(self):
        self.assertTrue((ROOT / ".github" / "ISSUE_TEMPLATE" / "bug_report.md").exists())
        self.assertTrue((ROOT / ".github" / "ISSUE_TEMPLATE" / "feature_request.md").exists())
        self.assertTrue((ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").exists())


class TestPackageSurface(unittest.TestCase):
    def test_public_api_exports(self):
        import pycorscage

        for name in (
            "parse_origin",
            "normalize_origin",
            "match_origin",
            "merge_vary",
            "create_cors_policy",
            "CorsPolicy",
            "CorsDecision",
            "WSGICorsMiddleware",
            "ASGICorsMiddleware",
            "lint_cors_config",
        ):
            self.assertTrue(hasattr(pycorscage, name), name)

    def test_version(self):
        import pycorscage

        self.assertEqual(pycorscage.__version__, "1.0.0")

    def test_no_runtime_imports_of_frameworks(self):
        forbidden = (b"import flask", b"import django", b"import fastapi", b"import starlette", b"import uvicorn")
        offenders = []
        for path in (ROOT / "src").rglob("*.py"):
            data = path.read_bytes().lower()
            if any(token in data for token in forbidden):
                offenders.append(str(path))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
