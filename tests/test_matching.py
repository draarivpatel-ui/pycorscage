"""Origin pattern matching and subdomain boundary tests."""

from __future__ import annotations

import unittest

from pycorscage import CorsInputError, match_origin
from pycorscage.origin import is_overbroad_wildcard_base, parse_origin_pattern

from _support import add_matrix_tests


EXACT_MATCH_CASES = [
    ("https://example.com", "https://example.com", True),
    ("HTTPS://EXAMPLE.COM", "https://example.com", True),
    ("https://example.com:443", "https://example.com", True),
    ("https://example.com", "https://example.com:443", True),
    ("https://example.com:444", "https://example.com", False),
    ("http://example.com", "https://example.com", False),
    ("https://www.example.com", "https://example.com", False),
    ("https://evil-example.com", "https://example.com", False),
    ("https://example.com.evil.example", "https://example.com", False),
    ("https://example.com.", "https://example.com", False),
    ("https://example.com/", "https://example.com", False),
    ("https://user@example.com", "https://example.com", False),
    ("https://example.com:0443", "https://example.com", False),
    ("null", "https://example.com", False),
    ("https://127.0.0.1", "https://127.0.0.1", True),
    ("https://127.0.0.2", "https://127.0.0.1", False),
    ("https://[::1]", "https://[::1]", True),
    ("https://[0:0:0:0:0:0:0:1]", "https://[::1]", True),
    ("https://[::2]", "https://[::1]", False),
]

SUBDOMAIN_CASES = [
    ("https://tenant.example.com", "https://*.example.com", False, True),
    ("https://TENANT.EXAMPLE.COM", "https://*.example.com", False, True),
    ("https://tenant.example.com:443", "https://*.example.com", False, True),
    ("https://tenant.example.com", "https://*.example.com:443", False, True),
    ("https://tenant.example.com:8443", "https://*.example.com", False, False),
    ("https://tenant.example.com:8443", "https://*.example.com:8443", False, True),
    ("https://example.com", "https://*.example.com", False, False),
    ("https://example.com", "https://*.example.com", True, False),
    ("https://deep.tenant.example.com", "https://*.example.com", False, False),
    ("https://deep.tenant.example.com", "https://*.example.com", True, True),
    ("https://very.deep.tenant.example.com", "https://*.example.com", True, True),
    ("https://evil-example.com", "https://*.example.com", False, False),
    ("https://evil-example.com", "https://*.example.com", True, False),
    ("https://example.com.evil.example", "https://*.example.com", False, False),
    ("https://example.com.evil.example", "https://*.example.com", True, False),
    ("http://tenant.example.com", "https://*.example.com", False, False),
    ("http://tenant.example.com", "https://*.example.com", True, False),
    ("https://127.0.0.1", "https://*.example.com", False, False),
    ("https://tenant.example.com.", "https://*.example.com", False, False),
    ("https://tenant..example.com", "https://*.example.com", False, False),
    ("https://.tenant.example.com", "https://*.example.com", False, False),
    ("https://tenant.example.com/path", "https://*.example.com", False, False),
]

VALID_SUFFIX_SCOPED_CASES = [
    ("https://app.example.co.uk", "https://*.example.co.uk"),
    ("https://app.example.com.au", "https://*.example.com.au"),
    ("https://app.example.co.jp", "https://*.example.co.jp"),
    ("https://app.example.com.cn", "https://*.example.com.cn"),
    ("https://app.example.com.br", "https://*.example.com.br"),
    ("https://app.example.co.nz", "https://*.example.co.nz"),
    ("https://app.example.co.in", "https://*.example.co.in"),
    ("https://app.example.com.sg", "https://*.example.com.sg"),
    ("https://app.example.co.kr", "https://*.example.co.kr"),
    ("https://app.example.github.io", "https://*.example.github.io"),
    ("https://app.example.pages.dev", "https://*.example.pages.dev"),
    ("https://app.example.vercel.app", "https://*.example.vercel.app"),
]

OVERBROAD_PATTERNS = [
    "https://*.com",
    "https://*.net",
    "https://*.org",
    "https://*.uk",
    "https://*.co.uk",
    "https://*.org.uk",
    "https://*.com.au",
    "https://*.co.jp",
    "https://*.com.cn",
    "https://*.com.br",
    "https://*.co.nz",
    "https://*.co.in",
    "https://*.com.sg",
    "https://*.co.kr",
    "https://*.github.io",
    "https://*.gitlab.io",
    "https://*.pages.dev",
    "https://*.vercel.app",
    "https://*.netlify.app",
    "https://*.herokuapp.com",
    "https://*.azurewebsites.net",
    "https://*.cloudfront.net",
    "https://*.workers.dev",
    "https://*.web.app",
    "https://*.firebaseapp.com",
    "https://*.appspot.com",
    "https://*.amazonaws.com",
    "https://*.localhost",
]

INVALID_PATTERN_CASES = [
    "",
    "example.com",
    "*example.com",
    "https://*example.com",
    "https://**example.com",
    "https://*.*.example.com",
    "https://example.*.com",
    "https://*.example*.com",
    "https://*.example.com*",
    "https://*.127.0.0.1",
    "https://*.[::1]",
    "https://*.example.com.",
    "https://*.example..com",
    "https://*.example.com:0443",
    "https://*.example.com:0",
    "https://*.example.com/path",
    "https://user@*.example.com",
    "https://%2a.example.com",
    "null",
    "NULL",
    "ftp://*.example.com",
]

HTTP_FLOOR_CASES = [
    ("http://example.com", "http://example.com", False, False),
    ("http://example.com", "*", False, False),
    ("http://example.com", "*", True, False),
    ("http://localhost", "http://localhost", False, True),
    ("http://localhost:3000", "http://localhost:3000", False, True),
    ("http://localhost:3001", "http://localhost:3000", False, False),
    ("http://app.localhost:3000", "http://app.localhost:3000", False, True),
    ("http://127.0.0.1:3000", "http://127.0.0.1:3000", False, True),
    ("http://127.255.0.1:3000", "http://127.255.0.1:3000", False, True),
    ("http://[::1]:3000", "http://[::1]:3000", False, True),
    ("http://localhost:3000", "*", False, False),
    ("http://localhost:3000", "*", True, True),
    ("http://app.localhost:3000", "*", True, True),
    ("http://127.0.0.1:3000", "*", True, True),
    ("http://example.com", "http://example.com", True, False),
    ("https://example.com", "*", False, True),
    ("https://example.com", "*", True, True),
]

INVALID_CANDIDATES = [
    "",
    "example.com",
    "https://example.com/",
    "https://user@example.com",
    "https://example.com,https://evil.example",
    "https://example.com\x00",
    "https://éxample.com",
    "https://0177.0.0.1",
    "https://example.com.",
    "https://example.com:0443",
    "null",
    "NULL",
]


class TestExactMatching(unittest.TestCase):
    def check_exact(self, case):
        candidate, pattern, expected = case
        self.assertIs(match_origin(candidate, pattern), expected)


add_matrix_tests(TestExactMatching, "exact", EXACT_MATCH_CASES, TestExactMatching.check_exact)


class TestSubdomainMatching(unittest.TestCase):
    def check_subdomain(self, case):
        candidate, pattern, multi, expected = case
        self.assertIs(match_origin(candidate, pattern, multi_level_subdomains=multi), expected)


add_matrix_tests(TestSubdomainMatching, "subdomain", SUBDOMAIN_CASES, TestSubdomainMatching.check_subdomain)


class TestPublicSuffixScoping(unittest.TestCase):
    def check_valid_scoped_suffix(self, case):
        candidate, pattern = case
        self.assertIs(match_origin(candidate, pattern), True)

    def check_overbroad(self, case):
        self.assertIs(match_origin("https://tenant" + case[case.find(".") + 1:] if False else "https://tenant.example.com", case), False)
        compiled = parse_origin_pattern(case)
        self.assertTrue(is_overbroad_wildcard_base(compiled.host or ""))


add_matrix_tests(TestPublicSuffixScoping, "valid_suffix_scope", VALID_SUFFIX_SCOPED_CASES, TestPublicSuffixScoping.check_valid_scoped_suffix)
add_matrix_tests(TestPublicSuffixScoping, "overbroad_suffix", OVERBROAD_PATTERNS, TestPublicSuffixScoping.check_overbroad)


class TestInvalidPatterns(unittest.TestCase):
    def check_invalid_pattern(self, case):
        self.assertIs(match_origin("https://tenant.example.com", case), False)


add_matrix_tests(TestInvalidPatterns, "invalid_pattern", INVALID_PATTERN_CASES, TestInvalidPatterns.check_invalid_pattern)


class TestHttpFloor(unittest.TestCase):
    def check_http_floor(self, case):
        candidate, pattern, allow_local, expected = case
        self.assertIs(match_origin(candidate, pattern, allow_http_localhost=allow_local), expected)


add_matrix_tests(TestHttpFloor, "http_floor", HTTP_FLOOR_CASES, TestHttpFloor.check_http_floor)


class TestInvalidCandidates(unittest.TestCase):
    def check_invalid_candidate(self, case):
        self.assertIs(match_origin(case, "*"), False)
        self.assertIs(match_origin(case, "https://example.com"), False)


add_matrix_tests(TestInvalidCandidates, "invalid_candidate", INVALID_CANDIDATES, TestInvalidCandidates.check_invalid_candidate)


class TestMatchingSpecificBehavior(unittest.TestCase):
    def test_boolean_options_reject_truthy_non_boolean(self):
        with self.assertRaises(CorsInputError):
            match_origin("https://a.example.com", "https://*.example.com", multi_level_subdomains=1)
        with self.assertRaises(CorsInputError):
            match_origin("https://a.example.com", "https://*.example.com", allow_http_localhost="yes")

    def test_long_single_label_match_is_safe(self):
        label = "a" * 63
        self.assertIs(match_origin("https://" + label + ".example.com", "https://*.example.com"), True)

    def test_long_nested_input_does_not_match_single_label_mode(self):
        labels = ".".join(["a" * 20] * 3)
        self.assertIs(match_origin("https://" + labels + ".example.com", "https://*.example.com"), False)
        self.assertIs(match_origin("https://" + labels + ".example.com", "https://*.example.com", multi_level_subdomains=True), True)

    def test_wrong_port_never_matches(self):
        self.assertIs(match_origin("https://a.example.com:444", "https://*.example.com:443"), False)

    def test_universal_wildcard_still_requires_valid_secure_origin(self):
        self.assertIs(match_origin("https://anything.example", "*"), True)
        self.assertIs(match_origin("http://anything.example", "*"), False)


if __name__ == "__main__":
    unittest.main()
