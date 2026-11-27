"""Structured configuration linter and runtime parity tests."""

from __future__ import annotations

import unittest

from pycorscage import CorsConfigError, create_cors_policy, lint_cors_config
from pycorscage.linter import LINT_CODES

from _support import add_matrix_tests


def codes(config):
    return {finding.code for finding in lint_cors_config(config)}


CODE_CASES = [
    ({"allowed_origins": ["*"], "allow_credentials": True}, "CORS_WILDCARD_WITH_CREDENTIALS"),
    ({"allowed_origins": ["*"]}, "CORS_REFLECT_ALL_ORIGINS"),
    ({"allow_null_origin": True}, "CORS_NULL_ORIGIN_ALLOWED"),
    ({"allow_null_origin": True, "allow_credentials": True}, "CORS_NULL_ORIGIN_ALLOWED"),
    ({"allowed_origins": ["*"], "allow_private_network": True}, "CORS_PRIVATE_NETWORK_WITH_WILDCARD"),
    ({"allowed_origins": ["https://*.example.com"], "allow_private_network": True}, "CORS_PRIVATE_NETWORK_WITH_WILDCARD"),
    ({"allowed_origins": ["http://example.com"]}, "CORS_INSECURE_HTTP_ORIGIN"),
    ({"allowed_origins": ["http://*.example.com"]}, "CORS_INSECURE_HTTP_ORIGIN"),
    ({"allowed_origins": ["http://localhost:3000"]}, "CORS_INSECURE_HTTP_ORIGIN"),
    ({"allowed_origins": ["https://*.com"]}, "CORS_OVERBROAD_SUBDOMAIN_WILDCARD"),
    ({"allowed_origins": ["https://*.co.uk"]}, "CORS_OVERBROAD_SUBDOMAIN_WILDCARD"),
    ({"allowed_origins": ["https://*.github.io"]}, "CORS_OVERBROAD_SUBDOMAIN_WILDCARD"),
    ({"allowed_origins": ["https://*.pages.dev"]}, "CORS_OVERBROAD_SUBDOMAIN_WILDCARD"),
    ({"expose_headers": ["set-cookie"]}, "CORS_UNSAFE_EXPOSE_HEADER"),
    ({"expose_headers": ["set-cookie2"]}, "CORS_UNSAFE_EXPOSE_HEADER"),
    ({"expose_headers": ["*"]}, "CORS_UNSAFE_EXPOSE_HEADER"),
    ({"expose_headers": ["bad header"]}, "CORS_UNSAFE_EXPOSE_HEADER"),
    ({"max_age": True}, "CORS_INVALID_MAX_AGE"),
    ({"max_age": 1.5}, "CORS_INVALID_MAX_AGE"),
    ({"max_age": -1}, "CORS_INVALID_MAX_AGE"),
    ({"max_age": 86401}, "CORS_INVALID_MAX_AGE"),
    ({"max_age": "600"}, "CORS_INVALID_MAX_AGE"),
    ({"allow_credentials": 1}, "CORS_INVALID_TYPE"),
    ({"allow_credentials": "true"}, "CORS_INVALID_TYPE"),
    ({"allow_private_network": None}, "CORS_INVALID_TYPE"),
    ({"max_request_headers": 0}, "CORS_INVALID_TYPE"),
    ({"max_request_headers": 129}, "CORS_INVALID_TYPE"),
    ({"max_request_headers_bytes": 127}, "CORS_INVALID_TYPE"),
    ({"max_request_headers_bytes": 16385}, "CORS_INVALID_TYPE"),
    ({"unknown_option": True}, "CORS_UNKNOWN_OPTION"),
    ({"allowed_origins": ["https://example.com/"]}, "CORS_INVALID_ORIGIN"),
    ({"allowed_origins": ["https://user@example.com"]}, "CORS_INVALID_ORIGIN"),
    ({"allowed_origins": ["null"]}, "CORS_INVALID_ORIGIN"),
    ({"allowed_origins": [None]}, "CORS_INVALID_TYPE"),
    ({"allowed_origins": 123}, "CORS_INVALID_TYPE"),
    ({"allowed_methods": ["TRACE"]}, "CORS_INVALID_METHOD"),
    ({"allowed_methods": ["CONNECT"]}, "CORS_INVALID_METHOD"),
    ({"allowed_methods": ["GET,POST"]}, "CORS_INVALID_METHOD"),
    ({"allowed_methods": []}, "CORS_INVALID_METHOD"),
    ({"allowed_methods": None}, "CORS_INVALID_TYPE"),
    ({"allowed_headers": ["*"]}, "CORS_INVALID_HEADER"),
    ({"allowed_headers": ["bad header"]}, "CORS_INVALID_HEADER"),
    ({"allowed_headers": ["cookie"]}, "CORS_UNSAFE_ALLOWED_HEADER"),
    ({"allowed_headers": ["host"]}, "CORS_UNSAFE_ALLOWED_HEADER"),
    ({"allowed_headers": ["sec-fetch-site"]}, "CORS_UNSAFE_ALLOWED_HEADER"),
    ({"allowed_headers": None}, "CORS_INVALID_TYPE"),
    ({"allowed_origins": ["https://a.example.com", "HTTPS://A.EXAMPLE.COM:443"]}, "CORS_DUPLICATE_ORIGIN"),
    ({}, "CORS_NO_ORIGINS_CONFIGURED"),
    ({"allowed_origins": ["*", "https://a.example.com"]}, "CORS_REDUNDANT_ORIGIN_ENTRY"),
    ({"allow_origin_predicate": "yes"}, "CORS_INVALID_TYPE"),
    ({"allow_origin_predicate": lambda origin: True}, "CORS_REFLECT_ALL_ORIGINS"),
    ({"allow_origin_predicate": lambda origin: True, "allow_credentials": True}, "CORS_REFLECT_ALL_ORIGINS"),
]

NONMAPPING_CASES = [None, True, False, 0, 1, "{}", [], object()]

RUNTIME_REJECTED_CONFIGS = [
    {"allowed_origins": ["*"], "allow_credentials": True},
    {"allow_null_origin": True, "allow_credentials": True},
    {"allowed_origins": ["*"], "allow_private_network": True},
    {"allowed_origins": ["http://example.com"]},
    {"allowed_origins": ["http://*.localhost"]},
    {"allowed_origins": ["https://*.com"]},
    {"expose_headers": ["set-cookie"]},
    {"max_age": True},
    {"max_age": 86401},
    {"allow_credentials": 1},
    {"allowed_methods": ["TRACE"]},
    {"allowed_headers": ["cookie"]},
    {"unknown_option": True},
]


class TestLintCodes(unittest.TestCase):
    def check_expected_code(self, case):
        config, expected = case
        self.assertIn(expected, codes(config))
        self.assertIn(expected, LINT_CODES)

    def test_findings_are_frozen_and_serializable(self):
        findings = lint_cors_config({"allowed_origins": ["*"], "allow_credentials": True})
        first = findings[0]
        with self.assertRaises(Exception):
            first.code = "CHANGED"
        as_dict = first.to_dict()
        self.assertEqual(as_dict["code"], first.code)
        self.assertIn(as_dict["severity"], {"critical", "high", "medium", "low"})

    def test_clean_exact_config_has_no_findings(self):
        config = {
            "allowed_origins": ["https://app.example.com"],
            "allowed_methods": ["GET", "POST"],
            "allowed_headers": ["content-type"],
            "expose_headers": ["x-request-id"],
            "max_age": 600,
        }
        self.assertEqual(lint_cors_config(config), ())

    def test_valid_country_suffix_wildcard_has_no_overbroad_finding(self):
        self.assertNotIn("CORS_OVERBROAD_SUBDOMAIN_WILDCARD", codes({"allowed_origins": ["https://*.example.co.uk"]}))

    def test_public_suffix_detector_is_conservative_not_complete(self):
        self.assertIn("CORS_OVERBROAD_SUBDOMAIN_WILDCARD", codes({"allowed_origins": ["https://*.com"]}))


add_matrix_tests(TestLintCodes, "lint_code", CODE_CASES, TestLintCodes.check_expected_code)


class TestLintInvalidContainers(unittest.TestCase):
    def check_nonmapping(self, case):
        findings = lint_cors_config(case)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "CORS_INVALID_TYPE")
        self.assertEqual(findings[0].severity, "critical")


add_matrix_tests(TestLintInvalidContainers, "nonmapping", NONMAPPING_CASES, TestLintInvalidContainers.check_nonmapping)


class TestRuntimeParity(unittest.TestCase):
    def check_runtime_rejected_has_blocking_lint(self, case):
        from pycorscage import CorsPolicy
        with self.assertRaises(CorsConfigError):
            CorsPolicy.from_dict(case)
        findings = lint_cors_config(case)
        self.assertTrue(findings)
        self.assertTrue(any(finding.severity in {"critical", "high"} for finding in findings))

    def test_linter_does_not_execute_predicate(self):
        calls = []

        def predicate(origin):
            calls.append(origin)
            return True

        lint_cors_config({"allow_origin_predicate": predicate})
        self.assertEqual(calls, [])

    def test_async_predicate_is_invalid(self):
        async def predicate(origin):
            return True

        self.assertIn("CORS_INVALID_TYPE", codes({"allow_origin_predicate": predicate}))

    def test_runtime_accepted_localhost_still_audited(self):
        config = {"allowed_origins": ["http://localhost:3000"]}
        create_cors_policy(**config)
        self.assertIn("CORS_INSECURE_HTTP_ORIGIN", codes(config))

    def test_browser_forbidden_header_opt_in_parity(self):
        config = {"allowed_headers": ["accept-encoding"], "allow_forbidden_headers": True}
        create_cors_policy(**config)
        self.assertNotIn("CORS_UNSAFE_ALLOWED_HEADER", codes(config))


add_matrix_tests(TestRuntimeParity, "runtime_rejected", RUNTIME_REJECTED_CONFIGS, TestRuntimeParity.check_runtime_rejected_has_blocking_lint)


if __name__ == "__main__":
    unittest.main()
