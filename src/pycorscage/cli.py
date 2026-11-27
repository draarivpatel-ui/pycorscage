"""Command-line CORS policy auditor and request evaluator."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import unicodedata
from collections.abc import Mapping
from typing import Optional, Sequence

from .errors import CorsCageError
from .linter import lint_cors_config
from .policy import CorsPolicy

MAX_CONFIG_BYTES = 1024 * 1024

_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def neutralize_text(value: object) -> str:
    """Remove terminal control sequences and control characters from output."""

    text = str(value)
    text = _OSC_RE.sub("", text)
    text = _CSI_RE.sub("", text)
    output = []
    for char in text:
        code = ord(char)
        if char in ("\n", "\t") or (32 <= code != 127 and not unicodedata.category(char).startswith("C")):
            output.append(char)
        else:
            output.append("?")
    return "".join(output)


def _out(text: str) -> None:
    sys.stdout.write(neutralize_text(text) + "\n")


def _err(text: str) -> None:
    sys.stderr.write(neutralize_text(text) + "\n")


class ConfigReadError(Exception):
    pass


def _object_without_duplicates(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON object key")
        output[key] = value
    return output


def read_config_file(path: str) -> Mapping[str, object]:
    """Read a bounded JSON config using a no-follow, nonblocking file open."""

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigReadError("cannot open config safely: " + exc.strerror) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ConfigReadError("config path is not a regular file")
        if info.st_size > MAX_CONFIG_BYTES:
            raise ConfigReadError("config file exceeds the 1048576 byte cap")
        chunks = []
        total = 0
        while total <= MAX_CONFIG_BYTES:
            chunk = os.read(fd, min(65536, MAX_CONFIG_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > MAX_CONFIG_BYTES:
            raise ConfigReadError("config file exceeds the 1048576 byte cap")
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigReadError("config file is not valid UTF-8") from exc
    try:
        parsed = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigReadError("config file is not valid strict JSON") from exc
    if not isinstance(parsed, Mapping):
        raise ConfigReadError("config JSON top level must be an object")
    return parsed


def _decision_to_dict(decision) -> dict:
    return {
        "allowed": decision.allowed,
        "is_preflight": decision.is_preflight,
        "status_code": decision.status_code,
        "headers": {name: value for name, value in decision.headers.items()},
        "vary": list(decision.vary),
        "reason": decision.reason,
        "code": decision.code,
        "origin": decision.origin,
    }


def _print_decision(decision) -> None:
    _out("allowed: " + ("yes" if decision.allowed else "no"))
    _out("preflight: " + ("yes" if decision.is_preflight else "no"))
    _out("status_code: " + ("none" if decision.status_code is None else str(decision.status_code)))
    _out("code: " + decision.code)
    _out("reason: " + decision.reason)
    if decision.origin is not None:
        _out("origin: " + decision.origin)
    if decision.vary:
        _out("vary: " + ", ".join(decision.vary))
    if decision.headers:
        _out("headers:")
        for name, value in decision.headers.items():
            _out("  " + name + ": " + value)


def _print_findings(findings) -> None:
    if not findings:
        _out("no findings")
        return
    for finding in findings:
        location = finding.path if finding.path is not None else "config"
        _out("[" + finding.severity + "] " + finding.code + " at " + location)
        _out("  " + finding.message)
        _out("  fix: " + finding.remediation)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pycorscage",
        description="Audit strict CORS policy JSON and evaluate browser CORS requests.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", help="evaluate one request against a policy")
    check.add_argument("--config", required=True, help="path to a strict JSON policy file")
    check.add_argument("--origin", required=True, help="Origin header value to evaluate")
    check.add_argument("--method", default="GET", help="request method, or Access-Control-Request-Method with --preflight")
    check.add_argument("--request-headers", default=None, help="comma-separated Access-Control-Request-Headers value")
    check.add_argument("--preflight", action="store_true", help="evaluate as an OPTIONS CORS preflight")
    check.add_argument("--private-network", action="store_true", help="send Access-Control-Request-Private-Network: true")
    check.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    lint = subparsers.add_parser("lint", help="audit a policy configuration")
    lint.add_argument("--config", required=True, help="path to a strict JSON policy file")
    lint.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    return parser


def _run_check(args: argparse.Namespace) -> int:
    try:
        config = read_config_file(args.config)
    except ConfigReadError as exc:
        _err("error: " + str(exc))
        return 2
    try:
        policy = CorsPolicy.from_dict(config)
    except CorsCageError as exc:
        _err("error: invalid policy configuration: " + exc.code + ": " + exc.reason)
        return 2

    headers = {"Origin": args.origin}
    evaluate_method = args.method
    if args.preflight:
        evaluate_method = "OPTIONS"
        headers["Access-Control-Request-Method"] = args.method
    if args.request_headers is not None:
        headers["Access-Control-Request-Headers"] = args.request_headers
    if args.private_network:
        headers["Access-Control-Request-Private-Network"] = "true"

    decision = policy.evaluate(evaluate_method, headers)
    if args.json:
        _out(json.dumps(_decision_to_dict(decision), sort_keys=True, separators=(",", ":")))
    else:
        _print_decision(decision)
    return 0 if decision.allowed else 1


def _run_lint(args: argparse.Namespace) -> int:
    try:
        config = read_config_file(args.config)
    except ConfigReadError as exc:
        _err("error: " + str(exc))
        return 2
    findings = lint_cors_config(config)
    if args.json:
        _out(json.dumps({"findings": [finding.to_dict() for finding in findings]}, sort_keys=True, separators=(",", ":")))
    else:
        _print_findings(findings)
    return 1 if findings else 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "check":
        return _run_check(args)
    if args.command == "lint":
        return _run_lint(args)
    return 2


__all__ = ["MAX_CONFIG_BYTES", "build_parser", "main", "neutralize_text", "read_config_file"]
