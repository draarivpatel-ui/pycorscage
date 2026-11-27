"""Policy configuration, immutability, actual-request, and predicate tests."""

from __future__ import annotations

import unittest

from pycorscage import CorsConfigError, CorsPolicy, create_cors_policy
from pycorscage.policy import CONFIG_KEYS

from _support import add_matrix_tests


BOOL_KEYS = [
    "allow_credentials",
    "allow_null_origin",
    "allow_http_localhost",
    "multi_level_subdomains",
    "allow_private_network",
    "allow_forbidden_headers",
]
INVALID_BOOL_VALUES = [None, 0, 1, "true", "false", [], object()]
INVALID_BOOL_CASES = [(key, value) for key in BOOL_KEYS for value in INVALID_BOOL_VALUES]

INVALID_MAX_AGE = [None, True, False, 1.0, "1", -1, -100, 86401, 86400.0, 10**10, object()]

INVALID_METHOD_VALUES = [
    "",
    "*",
    "TRACE",
    "trace",
    "CONNECT",
    "connect",
    "GET POST",
    "GET,POST",
    "GET\r",
    "POST\n",
    "G\x00ET",
    "é",
    "M" * 65,
    None,
    1,
    object(),
]

HARDFORBIDDEN_HEADERS = [
    "access-control-request-headers",
    "access-control-request-method",
    "access-control-request-private-network",
    "connection",
    "content-length",
    "host",
    "keep-alive",
    "origin",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
]
BROWSER_FORBIDDEN_HEADERS = [
    "accept-charset",
    "accept-encoding",
    "cookie",
    "cookie2",
    "date",
    "dnt",
    "expect",
    "referer",
    "sec-fetch-site",
    "proxy-authorization",
]
INVALID_HEADER_TOKENS = [
    "",
    "*",
    "bad header",
    "bad\theader",
    "bad\rheader",
    "bad\nheader",
    "bad\x00header",
    "é-header",
    "x" * 129,
    None,
    1,
    object(),
]

INVALID_EXPOSE_VALUES = [
    "set-cookie",
    "Set-Cookie",
    "set-cookie2",
    "*",
    "",
    "bad header",
    "bad\rheader",
    "é-header",
    "x" * 129,
    None,
    1,
]

INVALID_ORIGIN_ENTRIES = [
    "http://example.com",
    "http://example.com:8080",
    "http://*.example.com",
    "http://*.localhost",
    "https://*.com",
    "https://*.co.uk",
    "https://*.github.io",
    "https://*.localhost",
    "null",
    "https://example.com/",
    "https://user@example.com",
    "https://example.com,https://evil.example",
    "https://example.com.",
    "https://example.com:0443",
    "https://0177.0.0.1",
    "ftp://example.com",
    "",
    None,
    True,
    1,
    object(),
]

PREDICATE_RESULTS = [
    ("yes", False, "CORS_PREDICATE_INVALID_RESULT"),
    (1, False, "CORS_PREDICATE_INVALID_RESULT"),
    (0, False, "CORS_PREDICATE_INVALID_RESULT"),
    (None, False, "CORS_PREDICATE_INVALID_RESULT"),
    ([], False, "CORS_PREDICATE_INVALID_RESULT"),
    (True, True, "CORS_ORIGIN_ALLOWED"),
    (False, False, "CORS_ORIGIN_NOT_ALLOWED"),
]


class TestBooleanValidation(unittest.TestCase):
    def check_invalid_bool(self, case):
        key, value = case
        kwargs = {key: value}
        with self.assertRaises(CorsConfigError):
            create_cors_policy(**kwargs)


add_matrix_tests(TestBooleanValidation, "invalid_bool", INVALID_BOOL_CASES, TestBooleanValidation.check_invalid_bool)


class TestIntegerValidation(unittest.TestCase):
    def check_invalid_max_age(self, case):
        with self.assertRaises(CorsConfigError) as caught:
            create_cors_policy(max_age=case)
        self.assertEqual(caught.exception.code, "CORS_INVALID_MAX_AGE")

    def test_max_age_zero_boundary_valid(self):
        self.assertEqual(create_cors_policy(max_age=0).max_age, 0)

    def test_max_age_upper_boundary_valid(self):
        self.assertEqual(create_cors_policy(max_age=86400).max_age, 86400)

    def test_max_request_headers_bool_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(max_request_headers=True)

    def test_max_request_headers_zero_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(max_request_headers=0)

    def test_max_request_headers_upper_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(max_request_headers=129)

    def test_max_request_headers_bytes_low_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(max_request_headers_bytes=127)

    def test_max_request_headers_bytes_high_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(max_request_headers_bytes=16385)

    def test_max_request_headers_bytes_float_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(max_request_headers_bytes=2048.0)


add_matrix_tests(TestIntegerValidation, "invalid_max_age", INVALID_MAX_AGE, TestIntegerValidation.check_invalid_max_age)


class TestMethodValidation(unittest.TestCase):
    def check_invalid_method(self, case):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allowed_methods=[case])

    def test_empty_method_list_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allowed_methods=[])

    def test_default_methods(self):
        self.assertEqual(create_cors_policy().allowed_methods, ("GET", "HEAD", "POST"))

    def test_method_deduplication_preserves_order(self):
        policy = create_cors_policy(allowed_methods=["POST", "GET", "POST", "PATCH"])
        self.assertEqual(policy.allowed_methods, ("POST", "GET", "PATCH"))


add_matrix_tests(TestMethodValidation, "invalid_method", INVALID_METHOD_VALUES, TestMethodValidation.check_invalid_method)


class TestHeaderConfigValidation(unittest.TestCase):
    def check_hard_forbidden(self, case):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allowed_headers=[case], allow_forbidden_headers=True)

    def check_browser_forbidden(self, case):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allowed_headers=[case])

    def check_invalid_token(self, case):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allowed_headers=[case], allow_forbidden_headers=True)

    def test_browser_forbidden_explicit_opt_in(self):
        policy = create_cors_policy(allowed_headers=["accept-encoding"], allow_forbidden_headers=True)
        self.assertEqual(policy.allowed_headers, ("accept-encoding",))

    def test_header_deduplication_case_insensitive(self):
        policy = create_cors_policy(allowed_headers=["X-One", "x-one", "X-Two"])
        self.assertEqual(policy.allowed_headers, ("x-one", "x-two"))


add_matrix_tests(TestHeaderConfigValidation, "hard_forbidden_header", HARDFORBIDDEN_HEADERS, TestHeaderConfigValidation.check_hard_forbidden)
add_matrix_tests(TestHeaderConfigValidation, "browser_forbidden_header", BROWSER_FORBIDDEN_HEADERS, TestHeaderConfigValidation.check_browser_forbidden)
add_matrix_tests(TestHeaderConfigValidation, "invalid_header_token", INVALID_HEADER_TOKENS, TestHeaderConfigValidation.check_invalid_token)


class TestExposeValidation(unittest.TestCase):
    def check_invalid_expose(self, case):
        with self.assertRaises(CorsConfigError) as caught:
            create_cors_policy(expose_headers=[case])
        self.assertEqual(caught.exception.code, "CORS_UNSAFE_EXPOSE_HEADER")

    def test_valid_expose_headers_normalized(self):
        policy = create_cors_policy(expose_headers=["X-Request-Id", "x-request-id", "ETag"])
        self.assertEqual(policy.expose_headers, ("x-request-id", "etag"))


add_matrix_tests(TestExposeValidation, "invalid_expose", INVALID_EXPOSE_VALUES, TestExposeValidation.check_invalid_expose)


class TestOriginConfigValidation(unittest.TestCase):
    def check_invalid_origin_entry(self, case):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allowed_origins=[case])

    def test_unknown_option_rejected(self):
        with self.assertRaises(CorsConfigError) as caught:
            CorsPolicy.from_dict({"allowed_origins": ["https://a.example.com"], "typo_option": True})
        self.assertEqual(caught.exception.code, "CORS_UNKNOWN_OPTION")

    def test_exact_localhost_http_entry_accepted(self):
        policy = create_cors_policy(allowed_origins=["http://localhost:3000"])
        self.assertEqual(policy.allowed_origins, ("http://localhost:3000",))

    def test_exact_loopback_ipv4_http_entry_accepted(self):
        policy = create_cors_policy(allowed_origins=["http://127.0.0.1:3000"])
        self.assertTrue(policy.is_origin_allowed("http://127.0.0.1:3000"))

    def test_duplicate_origins_canonicalized_away(self):
        policy = create_cors_policy(allowed_origins=["HTTPS://EXAMPLE.COM:443", "https://example.com"])
        self.assertEqual(policy.allowed_origins, ("https://example.com",))

    def test_wildcard_with_credentials_hard_error(self):
        with self.assertRaises(CorsConfigError) as caught:
            create_cors_policy(allowed_origins=["*"], allow_credentials=True)
        self.assertEqual(caught.exception.code, "CORS_WILDCARD_WITH_CREDENTIALS")

    def test_null_with_credentials_hard_error(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allow_null_origin=True, allow_credentials=True)

    def test_private_network_with_universal_hard_error(self):
        with self.assertRaises(CorsConfigError) as caught:
            create_cors_policy(allowed_origins=["*"], allow_private_network=True)
        self.assertEqual(caught.exception.code, "CORS_PRIVATE_NETWORK_WITH_WILDCARD")


add_matrix_tests(TestOriginConfigValidation, "invalid_origin_entry", INVALID_ORIGIN_ENTRIES, TestOriginConfigValidation.check_invalid_origin_entry)


class TestPolicyImmutability(unittest.TestCase):
    def test_attribute_assignment_blocked(self):
        policy = create_cors_policy()
        with self.assertRaises(AttributeError):
            policy.allow_credentials = True

    def test_attribute_deletion_blocked(self):
        policy = create_cors_policy()
        with self.assertRaises(AttributeError):
            del policy.allow_credentials

    def test_allowed_tuple_mutation_blocked(self):
        policy = create_cors_policy(allowed_origins=["https://a.example.com"])
        with self.assertRaises(AttributeError):
            policy.allowed_origins += ("https://evil.example",)

    def test_config_view_mutation_blocked(self):
        policy = create_cors_policy()
        with self.assertRaises(TypeError):
            policy.config["allow_credentials"] = True

    def test_runtime_wildcard_credentials_tamper_hard_error(self):
        policy = create_cors_policy(allowed_origins=["*"])
        object.__setattr__(policy, "allow_credentials", True)
        with self.assertRaises(CorsConfigError):
            policy.evaluate("GET", {"Origin": "https://a.example.com"})

    def test_runtime_private_network_tamper_hard_error(self):
        policy = create_cors_policy(allowed_origins=["*"])
        object.__setattr__(policy, "allow_private_network", True)
        with self.assertRaises(CorsConfigError):
            policy.evaluate("GET", {"Origin": "https://a.example.com"})


class TestActualEvaluation(unittest.TestCase):
    def test_no_origin_is_not_cors_and_passes_without_headers(self):
        decision = create_cors_policy().evaluate("GET", {})
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.status_code)
        self.assertEqual(decision.code, "CORS_NO_ORIGIN")
        self.assertEqual(decision.headers.as_list(), [])
        self.assertEqual(decision.vary, ("Origin",))

    def test_exact_allowed_actual_response(self):
        policy = create_cors_policy(
            allowed_origins=["https://app.example.com"],
            allow_credentials=True,
            expose_headers=["x-request-id"],
        )
        decision = policy.evaluate("GET", {"Origin": "HTTPS://APP.EXAMPLE.COM:443"})
        self.assertTrue(decision.allowed)
        self.assertIsNone(decision.status_code)
        self.assertEqual(decision.headers["access-control-allow-origin"], "https://app.example.com")
        self.assertEqual(decision.headers["access-control-allow-credentials"], "true")
        self.assertEqual(decision.headers["access-control-expose-headers"], "x-request-id")
        self.assertNotIn("access-control-allow-methods", decision.headers)

    def test_disallowed_actual_response_has_no_grant(self):
        policy = create_cors_policy(allowed_origins=["https://app.example.com"])
        decision = policy.evaluate("POST", {"Origin": "https://evil.example"})
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.status_code)
        self.assertEqual(decision.code, "CORS_ORIGIN_NOT_ALLOWED")
        self.assertEqual(decision.headers.as_list(), [])
        self.assertEqual(decision.vary, ("Origin",))

    def test_repeated_origin_header_denied(self):
        policy = create_cors_policy(allowed_origins=["https://app.example.com"])
        headers = [("Origin", "https://app.example.com"), ("origin", "https://app.example.com")]
        decision = policy.evaluate("GET", headers)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_ORIGIN_MALFORMED")

    def test_case_variant_duplicate_origin_mapping_denied(self):
        policy = create_cors_policy(allowed_origins=["https://app.example.com"])
        decision = policy.evaluate("GET", {"Origin": "https://app.example.com", "origin": "https://app.example.com"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_ORIGIN_MALFORMED")

    def test_comma_origin_denied_even_when_one_half_matches(self):
        policy = create_cors_policy(allowed_origins=["https://app.example.com"])
        decision = policy.evaluate("GET", {"Origin": "https://app.example.com,https://evil.example"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_ORIGIN_MULTIPLE")

    def test_null_denied_by_default(self):
        decision = create_cors_policy().evaluate("GET", {"Origin": "null"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_NULL_ORIGIN")

    def test_null_explicitly_allowed_without_credentials(self):
        policy = create_cors_policy(allow_null_origin=True)
        decision = policy.evaluate("GET", {"Origin": "null"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.headers["access-control-allow-origin"], "null")
        self.assertNotIn("access-control-allow-credentials", decision.headers)

    def test_universal_wildcard_echoes_star(self):
        policy = create_cors_policy(allowed_origins=["*"])
        decision = policy.evaluate("GET", {"Origin": "https://anything.example"})
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.headers["access-control-allow-origin"], "*")

    def test_nonlocal_http_never_authorized_by_universal(self):
        policy = create_cors_policy(allowed_origins=["*"])
        decision = policy.evaluate("GET", {"Origin": "http://example.com"})
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "CORS_INSECURE_HTTP_ORIGIN")

    def test_allow_http_localhost_permits_universal_loopback(self):
        policy = create_cors_policy(allowed_origins=["*"], allow_http_localhost=True)
        decision = policy.evaluate("GET", {"Origin": "http://localhost:3000"})
        self.assertTrue(decision.allowed)

    def test_exact_localhost_http_entry_works_without_global_opt_in(self):
        policy = create_cors_policy(allowed_origins=["http://localhost:3000"])
        self.assertTrue(policy.evaluate("GET", {"Origin": "http://localhost:3000"}).allowed)
        self.assertFalse(policy.evaluate("GET", {"Origin": "http://localhost:3001"}).allowed)

    def test_decision_is_frozen(self):
        decision = create_cors_policy().evaluate("GET", {})
        with self.assertRaises(Exception):
            decision.allowed = True

    def test_decision_headers_case_insensitive(self):
        policy = create_cors_policy(allowed_origins=["https://a.example.com"])
        decision = policy.evaluate("GET", {"Origin": "https://a.example.com"})
        self.assertEqual(decision.headers["ACCESS-CONTROL-ALLOW-ORIGIN"], "https://a.example.com")


class TestPredicateBehavior(unittest.TestCase):
    def check_predicate_result(self, case):
        result, expected_allowed, expected_code = case
        policy = create_cors_policy(allow_origin_predicate=lambda origin: result)
        decision = policy.evaluate("GET", {"Origin": "https://lambda.example.com"})
        self.assertIs(decision.allowed, expected_allowed)
        self.assertEqual(decision.code, expected_code)

    def test_predicate_exception_fails_closed(self):
        def explode(origin):
            raise RuntimeError("untrusted callback failure")

        policy = create_cors_policy(allow_origin_predicate=explode)
        decision = policy.evaluate("GET", {"Origin": "https://a.example.com"})
        self.assertFalse(decision.allowed)

    def test_predicate_receives_parsed_origin(self):
        seen = []

        def predicate(origin):
            seen.append((origin.normalized, origin.scheme, origin.host, origin.port, origin.host_type))
            return True

        policy = create_cors_policy(allow_origin_predicate=predicate)
        self.assertTrue(policy.evaluate("GET", {"Origin": "HTTPS://A.EXAMPLE.COM:443"}).allowed)
        self.assertEqual(seen, [("https://a.example.com", "https", "a.example.com", 443, "domain")])

    def test_predicate_not_called_for_null(self):
        calls = []
        policy = create_cors_policy(allow_null_origin=False, allow_origin_predicate=lambda origin: calls.append(origin) or True)
        self.assertFalse(policy.evaluate("GET", {"Origin": "null"}).allowed)
        self.assertEqual(calls, [])

    def test_predicate_not_called_for_malformed(self):
        calls = []
        policy = create_cors_policy(allow_origin_predicate=lambda origin: calls.append(origin) or True)
        self.assertFalse(policy.evaluate("GET", {"Origin": "https://user@example.com"}).allowed)
        self.assertEqual(calls, [])

    def test_predicate_not_called_for_nonlocal_http(self):
        calls = []
        policy = create_cors_policy(allow_origin_predicate=lambda origin: calls.append(origin) or True)
        self.assertFalse(policy.evaluate("GET", {"Origin": "http://example.com"}).allowed)
        self.assertEqual(calls, [])

    def test_predicate_localhost_http_requires_opt_in(self):
        policy = create_cors_policy(allow_origin_predicate=lambda origin: True)
        self.assertFalse(policy.evaluate("GET", {"Origin": "http://localhost:3000"}).allowed)
        permissive = create_cors_policy(allow_origin_predicate=lambda origin: True, allow_http_localhost=True)
        self.assertTrue(permissive.evaluate("GET", {"Origin": "http://localhost:3000"}).allowed)

    def test_async_function_rejected_at_config_creation(self):
        async def predicate(origin):
            return True

        with self.assertRaises(CorsConfigError):
            create_cors_policy(allow_origin_predicate=predicate)

    def test_noncallable_predicate_rejected(self):
        with self.assertRaises(CorsConfigError):
            create_cors_policy(allow_origin_predicate="yes")


add_matrix_tests(TestPredicateBehavior, "predicate_result", PREDICATE_RESULTS, TestPredicateBehavior.check_predicate_result)


class TestConfigKeyRobustness(unittest.TestCase):
    def test_mixed_type_unknown_keys_raise_config_error_not_type_error(self):
        with self.assertRaises(CorsConfigError):
            CorsPolicy.from_dict({1: True, "unknown_option": True})

    def test_nonstring_unknown_key_raises_config_error(self):
        with self.assertRaises(CorsConfigError):
            CorsPolicy.from_dict({1: True})


if __name__ == "__main__":
    unittest.main()
