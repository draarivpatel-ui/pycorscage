"""Strict CORS preflight evaluation tests."""

from __future__ import annotations

import unittest

from pycorscage import create_cors_policy

from _support import add_matrix_tests


def base_policy(**overrides):
    config = {
        "allowed_origins": ["https://app.example.com"],
        "allowed_methods": ["GET", "POST", "PATCH", "X-CUSTOM"],
        "allowed_headers": ["content-type", "authorization", "x-one", "x-two"],
        "max_age": 60,
    }
    config.update(overrides)
    return create_cors_policy(**config)


VALID_PREFLIGHT_CASES = [
    ("GET", None, "GET", None),
    ("POST", None, "POST", None),
    ("PATCH", None, "PATCH", None),
    ("X-CUSTOM", None, "X-CUSTOM", None),
    ("POST", "content-type", "POST", "content-type"),
    ("POST", "Content-Type", "POST", "content-type"),
    ("POST", "content-type, authorization", "POST", "content-type, authorization"),
    ("POST", " x-one , x-two ", "POST", "x-one, x-two"),
    ("POST", "x-one,x-one,x-two", "POST", "x-one, x-two"),
    ("GET", "", None, None),
]

INVALID_METHODS = [
    "",
    "*",
    "TRACE",
    "trace",
    "CONNECT",
    "connect",
    "GET,POST",
    "GET POST",
    " GET",
    "GET ",
    "GET\r",
    "GET\n",
    "G\x00ET",
    "é",
    "M" * 65,
]

DISALLOWED_METHODS = [
    "DELETE",
    "PUT",
    "OPTIONS",
    "get",
    "post",
    "PATCHES",
    "X-CUSTOM-EXTRA",
]

MALFORMED_REQUEST_HEADERS = [
    "",
    ",",
    ",x-one",
    "x-one,",
    "x-one,,x-two",
    " ",
    "bad header",
    "bad\theader",
    "bad\rheader",
    "bad\nheader",
    "bad\x00header",
    "é-header",
    "*",
    "x" * 129,
]

PNA_MALFORMED_VALUES = [
    "false",
    "True",
    "TRUE",
    " true",
    "true ",
    "true,true",
    "1",
    "yes",
]


class TestValidPreflights(unittest.TestCase):
    def check_valid_preflight(self, case):
        method, raw_headers, expected_method, expected_headers = case
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": method,
        }
        if raw_headers is not None:
            headers["Access-Control-Request-Headers"] = raw_headers
        decision = base_policy().evaluate("OPTIONS", headers)
        if raw_headers == "":
            self.assertFalse(decision.allowed)
            self.assertEqual(decision.code, "CORS_HEADERS_MALFORMED")
            return
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.is_preflight)
        self.assertEqual(decision.status_code, 204)
        self.assertEqual(decision.code, "CORS_PREFLIGHT_ALLOWED")
        self.assertEqual(decision.headers["access-control-allow-methods"], expected_method)
        if expected_headers is None:
            self.assertNotIn("access-control-allow-headers", decision.headers)
        else:
            self.assertEqual(decision.headers["access-control-allow-headers"], expected_headers)
        self.assertEqual(decision.headers["access-control-max-age"], "60")
        self.assertEqual(
            decision.vary,
            (
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
                "Access-Control-Request-Private-Network",
            ),
        )


add_matrix_tests(TestValidPreflights, "valid_preflight", VALID_PREFLIGHT_CASES, TestValidPreflights.check_valid_preflight)


class TestPreflightMethodValidation(unittest.TestCase):
    def check_invalid_method(self, case):
        decision = base_policy().evaluate(
            "OPTIONS",
            {"Origin": "https://app.example.com", "Access-Control-Request-Method": case},
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 403)
        self.assertEqual(decision.code, "CORS_PREFLIGHT_METHOD_MALFORMED")
        self.assertEqual(decision.headers.as_list(), [])

    def check_disallowed_method(self, case):
        decision = base_policy().evaluate(
            "OPTIONS",
            {"Origin": "https://app.example.com", "Access-Control-Request-Method": case},
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 403)
        self.assertEqual(decision.code, "CORS_METHOD_NOT_ALLOWED")


add_matrix_tests(TestPreflightMethodValidation, "invalid_method", INVALID_METHODS, TestPreflightMethodValidation.check_invalid_method)
add_matrix_tests(TestPreflightMethodValidation, "disallowed_method", DISALLOWED_METHODS, TestPreflightMethodValidation.check_disallowed_method)


class TestRequestHeaderValidation(unittest.TestCase):
    def check_malformed_header_list(self, case):
        decision = base_policy().evaluate(
            "OPTIONS",
            {
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": case,
            },
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status_code, 403)
        self.assertEqual(decision.code, "CORS_HEADERS_MALFORMED")

    def test_unlisted_header_denied(self):
        decision = base_policy().evaluate(
            "OPTIONS",
            {
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-three",
            },
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_HEADERS_NOT_ALLOWED")

    def test_count_cap_default_32_boundary(self):
        names = ["x" + format(index, "02d") for index in range(32)]
        policy = base_policy(allowed_headers=names)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": ",".join(names),
        }
        self.assertTrue(policy.evaluate("OPTIONS", headers).allowed)

    def test_count_cap_default_33_rejected(self):
        names = ["x" + format(index, "02d") for index in range(33)]
        policy = base_policy(allowed_headers=names)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": ",".join(names),
        }
        decision = policy.evaluate("OPTIONS", headers)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_HEADERS_MALFORMED")

    def test_custom_count_cap_boundary(self):
        policy = base_policy(max_request_headers=2)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-one,x-two",
        }
        self.assertTrue(policy.evaluate("OPTIONS", headers).allowed)

    def test_custom_count_cap_exceeded(self):
        policy = base_policy(max_request_headers=2)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-one,x-two,x-one",
        }
        self.assertFalse(policy.evaluate("OPTIONS", headers).allowed)

    def test_duplicates_do_not_bypass_count_cap(self):
        policy = base_policy(max_request_headers=1)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "x-one,x-one",
        }
        self.assertFalse(policy.evaluate("OPTIONS", headers).allowed)

    def test_custom_byte_cap_boundary(self):
        first = "x" * 50
        second = "y" * 50
        third = "z" * 24
        policy = base_policy(allowed_headers=[first, second, third], max_request_headers_bytes=128)
        raw = first + "," + second + "," + third
        self.assertEqual(len(raw), 126)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": raw,
        }
        self.assertTrue(policy.evaluate("OPTIONS", headers).allowed)

    def test_custom_byte_cap_exceeded(self):
        first = "x" * 50
        second = "y" * 50
        third = "z" * 27
        policy = base_policy(allowed_headers=[first, second, third], max_request_headers_bytes=128)
        raw = first + "," + second + "," + third
        self.assertEqual(len(raw), 129)
        headers = {
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": raw,
        }
        decision = policy.evaluate("OPTIONS", headers)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_HEADERS_MALFORMED")

    def test_repeated_request_headers_control_header_denied(self):
        policy = base_policy()
        decision = policy.evaluate(
            "OPTIONS",
            [
                ("Origin", "https://app.example.com"),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Headers", "x-one"),
                ("access-control-request-headers", "x-one"),
            ],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_HEADERS_MALFORMED")


add_matrix_tests(TestRequestHeaderValidation, "malformed_request_headers", MALFORMED_REQUEST_HEADERS, TestRequestHeaderValidation.check_malformed_header_list)


class TestPrivateNetworkAccess(unittest.TestCase):
    def check_malformed_pna(self, case):
        policy = base_policy(allow_private_network=True)
        decision = policy.evaluate(
            "OPTIONS",
            {
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Private-Network": case,
            },
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_PRIVATE_NETWORK_MALFORMED")

    def test_pna_exact_opt_in_emits_header(self):
        policy = base_policy(allow_private_network=True)
        decision = policy.evaluate(
            "OPTIONS",
            {
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.headers["access-control-allow-private-network"], "true")

    def test_pna_denied_by_default(self):
        decision = base_policy().evaluate(
            "OPTIONS",
            {
                "Origin": "https://app.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_PRIVATE_NETWORK_DENIED")

    def test_pna_absent_does_not_emit_header(self):
        policy = base_policy(allow_private_network=True)
        decision = policy.evaluate(
            "OPTIONS",
            {"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST"},
        )
        self.assertTrue(decision.allowed)
        self.assertNotIn("access-control-allow-private-network", decision.headers)

    def test_pna_repeated_header_denied(self):
        policy = base_policy(allow_private_network=True)
        decision = policy.evaluate(
            "OPTIONS",
            [
                ("Origin", "https://app.example.com"),
                ("Access-Control-Request-Method", "POST"),
                ("Access-Control-Request-Private-Network", "true"),
                ("access-control-request-private-network", "true"),
            ],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_PRIVATE_NETWORK_MALFORMED")

    def test_pna_null_origin_denied(self):
        policy = create_cors_policy(
            allow_null_origin=True,
            allow_private_network=True,
            allowed_methods=["POST"],
        )
        decision = policy.evaluate(
            "OPTIONS",
            {
                "Origin": "null",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_PRIVATE_NETWORK_DENIED")

    def test_pna_subdomain_match_can_emit_when_explicitly_enabled(self):
        policy = create_cors_policy(
            allowed_origins=["https://*.example.com"],
            allow_private_network=True,
            allowed_methods=["POST"],
        )
        decision = policy.evaluate(
            "OPTIONS",
            {
                "Origin": "https://tenant.example.com",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.headers["access-control-allow-private-network"], "true")

    def test_pna_disallowed_origin_never_emits(self):
        policy = base_policy(allow_private_network=True)
        decision = policy.evaluate(
            "OPTIONS",
            {
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Private-Network": "true",
            },
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.headers.as_list(), [])


add_matrix_tests(TestPrivateNetworkAccess, "malformed_pna", PNA_MALFORMED_VALUES, TestPrivateNetworkAccess.check_malformed_pna)


class TestPreflightDistinction(unittest.TestCase):
    def test_plain_options_is_actual_request(self):
        decision = base_policy().evaluate("OPTIONS", {"Origin": "https://app.example.com"})
        self.assertFalse(decision.is_preflight)
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.status_code)
        self.assertNotIn("access-control-allow-methods", decision.headers)
        self.assertNotIn("access-control-max-age", decision.headers)

    def test_options_with_acrm_is_preflight_even_when_malformed(self):
        decision = base_policy().evaluate(
            "OPTIONS",
            {"Origin": "https://app.example.com", "Access-Control-Request-Method": "TRACE"},
        )
        self.assertTrue(decision.is_preflight)
        self.assertEqual(decision.status_code, 403)

    def test_acrm_on_get_is_not_preflight(self):
        decision = base_policy().evaluate(
            "GET",
            {"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST"},
        )
        self.assertFalse(decision.is_preflight)
        self.assertIsNone(decision.status_code)

    def test_acrm_without_origin_is_not_preflight(self):
        decision = base_policy().evaluate("OPTIONS", {"Access-Control-Request-Method": "POST"})
        self.assertFalse(decision.is_preflight)
        self.assertEqual(decision.code, "CORS_NO_ORIGIN")
        self.assertIsNone(decision.status_code)

    def test_lowercase_options_is_not_preflight(self):
        decision = base_policy().evaluate(
            "options",
            {"Origin": "https://app.example.com", "Access-Control-Request-Method": "POST"},
        )
        self.assertFalse(decision.is_preflight)
        self.assertIsNone(decision.status_code)

    def test_repeated_acrm_header_denied(self):
        decision = base_policy().evaluate(
            "OPTIONS",
            [
                ("Origin", "https://app.example.com"),
                ("Access-Control-Request-Method", "POST"),
                ("access-control-request-method", "POST"),
            ],
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_PREFLIGHT_METHOD_MALFORMED")

    def test_disallowed_origin_preflight_is_403(self):
        decision = base_policy().evaluate(
            "OPTIONS",
            {"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
        )
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.is_preflight)
        self.assertEqual(decision.status_code, 403)
        self.assertEqual(decision.headers.as_list(), [])


if __name__ == "__main__":
    unittest.main()
