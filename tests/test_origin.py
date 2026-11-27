"""Strict origin parser and canonicalization tests."""

from __future__ import annotations

import dataclasses
import unittest

from pycorscage import OriginParseError, normalize_origin, parse_origin, try_parse_origin

from _support import add_matrix_tests


VALID_CASES = [
    ("https://example.com", "https://example.com", 443),
    ("http://example.com", "http://example.com", 80),
    ("HTTPS://EXAMPLE.COM", "https://example.com", 443),
    ("HtTp://ExAmPlE.CoM", "http://example.com", 80),
    ("https://example.com:443", "https://example.com", 443),
    ("http://example.com:80", "http://example.com", 80),
    ("https://example.com:8443", "https://example.com:8443", 8443),
    ("http://example.com:8080", "http://example.com:8080", 8080),
    ("https://localhost", "https://localhost", 443),
    ("http://localhost:3000", "http://localhost:3000", 3000),
    ("https://app.localhost", "https://app.localhost", 443),
    ("https://intranet", "https://intranet", 443),
    ("https://xn--nxasmq6b.example.com", "https://xn--nxasmq6b.example.com", 443),
    ("https://127.0.0.1", "https://127.0.0.1", 443),
    ("https://255.255.255.255:65535", "https://255.255.255.255:65535", 65535),
    ("https://[::1]", "https://[::1]", 443),
    ("https://[2001:0db8:0:0:0:ff00:0042:8329]", "https://[2001:db8::ff00:42:8329]", 443),
    ("https://[::ffff:192.0.2.1]:8443", "https://[::ffff:c000:201]:8443", 8443),
    ("http://[2001:db8::]:80", "http://[2001:db8::]", 80),
    ("https://[0:0:0:0:0:0:0:0]", "https://[::]", 443),
]

VALID_PORTS = [
    ("https://example.com:1", 1),
    ("https://example.com:2", 2),
    ("https://example.com:79", 79),
    ("https://example.com:81", 81),
    ("https://example.com:442", 442),
    ("https://example.com:444", 444),
    ("https://example.com:8080", 8080),
    ("https://example.com:65534", 65534),
    ("https://example.com:65535", 65535),
]

VALID_IPV4 = [
    "https://0.0.0.0",
    "https://1.2.3.4",
    "https://10.0.0.1",
    "https://127.0.0.1",
    "https://192.168.1.20",
    "https://255.255.255.255",
]

IPV6_CANONICAL = [
    ("https://[0:0:0:0:0:0:0:1]", "https://[::1]"),
    ("https://[2001:DB8:0:0:0:0:0:1]", "https://[2001:db8::1]"),
    ("https://[2001:0:0:1:0:0:1:1]", "https://[2001::1:0:0:1:1]"),
    ("https://[0:0:1:0:0:1:0:0]", "https://[::1:0:0:1:0:0]"),
    ("https://[1:0:0:2:0:0:3:4]", "https://[1::2:0:0:3:4]"),
    ("https://[::ffff:1.2.3.4]", "https://[::ffff:102:304]"),
    ("https://[64:ff9b::192.0.2.33]", "https://[64:ff9b::c000:221]"),
]

INVALID_TYPES = [
    None,
    0,
    1,
    False,
    True,
    {},
    [],
    object(),
    b"https://example.com",
]

WHITESPACE_AND_CONTROL = [
    " https://example.com",
    "https://example.com ",
    "\thttps://example.com",
    "https://example.com\t",
    "\nhttps://example.com",
    "https://example.com\n",
    "\rhttps://example.com",
    "https://example.com\r",
    "https://exa mple.com",
    "https://example.com/\n",
    "https://example.com\r\n",
    "https://example.com\u0000",
    "https://example.com\u0001",
    "https://example.com\u0007",
    "https://example.com\u000b",
    "https://example.com\u000c",
    "https://example.com\u001f",
    "https://example.com\u007f",
    "https:// example.com",
    "https ://example.com",
    "https://example.com :443",
    "https://example.com:443 ",
    "  ",
    "\u00a0https://example.com",
    "https://example.com\u00a0",
]

NON_ASCII = [
    "https://éxample.com",
    "https://\u0435xample.com",
    "https://ex\u0430mple.com",
    "https://example。com",
    "https://example．com",
    "https://ｅｘａｍｐｌｅ.com",
    "https://παράδειγμα.example",
    "https://مثال.example",
    "https://例子.example",
    "https://example.com/\u00e9",
    "https://\u2024example.com",
    "https://ex\u200bample.com",
    "https://ex\u2060ample.com",
    "https://ex\ufeffample.com",
    "https://💥.example.com",
    "https://ex\u202eample.com",
]

STRUCTURAL_INVALID = [
    "",
    "example.com",
    "//example.com",
    "https:example.com",
    "https:/example.com",
    "https//example.com",
    "https://",
    "https:///example.com",
    "javascript://example.com",
    "data://example.com",
    "file://example.com",
    "ftp://example.com",
    "chrome-extension://abcdef",
    "about://blank",
    "https://example.com/",
    "https://example.com/path",
    "https://example.com/path/",
    "https://example.com?x=1",
    "https://example.com#frag",
    "https://example.com\\evil.example",
    "https://example.com/%2f",
    "https://user@example.com",
    "https://user:pass@example.com",
    "https://@example.com",
    "https://example.com@evil.example",
    "https://%65xample.com",
    "https://example%2ecom",
    "https://example.com%00",
    "https://example.com,https://evil.example",
    "https://example.com,null",
    "null,https://example.com",
    "https://example.com https://evil.example",
    "https://example.com;param",
    "https://example.com&x",
    "https://example.com=x",
    "https://example.com+evil",
    "https://exam_ple.com",
    "https://example..com",
    "https://.example.com",
    "https://example.com.",
    "https://-example.com",
    "https://example-.com",
    "https://exa--mple.com/path",
]

INVALID_PORTS = [
    "https://example.com:",
    "https://example.com:abc",
    "https://example.com:80a",
    "https://example.com:+80",
    "https://example.com:-80",
    "https://example.com: 80",
    "https://example.com:08",
    "https://example.com:080",
    "https://example.com:0443",
    "https://example.com:000443",
    "https://example.com:0",
    "https://example.com:00",
    "https://example.com:65536",
    "https://example.com:65537",
    "https://example.com:99999",
    "https://example.com:100000",
    "https://example.com:1.5",
    "https://example.com:0x50",
    "https://example.com:443/",
]

INVALID_IPV4 = [
    "https://127.1",
    "https://127.0.1",
    "https://127.0.0.0.1",
    "https://256.0.0.1",
    "https://999.999.999.999",
    "https://01.2.3.4",
    "https://001.2.3.4",
    "https://1.02.3.4",
    "https://1.2.003.4",
    "https://1.2.3.004",
    "https://0x7f.0.0.1",
    "https://0X7F.0.0.1",
    "https://0177.0.0.1",
    "https://0x7f",
    "https://0x",
    "https://0X",
    "https://0x.1",
    "https://0xg.1",
    "https://09",
    "https://2130706433",
    "https://127..0.1",
    "https://127...1",
    "https://1.2.3.",
    "https://.1.2.3",
    "https://1.2.3.4.5",
    "https://1234",
    "https://999999",
    "https://1.2.3.256",
    "https://example.123",
    "https://example.09",
]

INVALID_IPV6 = [
    "https://::1",
    "https://[::1",
    "https://::1]",
    "https://[]",
    "https://[",
    "https://]",
    "https://[::1]x",
    "https://[::1]evil",
    "https://[::1]:",
    "https://[::1]:abc",
    "https://[::1]:0",
    "https://[::1]:065535",
    "https://[:::]",
    "https://[::::]",
    "https://[1::2::3]",
    "https://[1:2:3:4:5:6:7:8:9]",
    "https://[1:2:3:4:5:6:7]",
    "https://[gggg::]",
    "https://[12345::]",
    "https://[::ffff:999.1.1.1]",
    "https://[::ffff:192.168.1]",
    "https://[::ffff:192.168.1.1.1]",
    "https://[fe80::1%25eth0]",
    "https://[fe80::1%eth0]",
    "https://[::1]/",
    "https://[::1]?x=1",
    "https://[::1]#x",
]


class TestValidOrigins(unittest.TestCase):
    def check_valid(self, case):
        value, normalized, port = case
        parsed = parse_origin(value)
        self.assertTrue(parsed.valid)
        self.assertFalse(parsed.is_null)
        self.assertEqual(parsed.normalized, normalized)
        self.assertEqual(parsed.port, port)
        self.assertEqual(normalize_origin(value), normalized)
        self.assertEqual(try_parse_origin(value), parsed)


add_matrix_tests(TestValidOrigins, "valid_origin", VALID_CASES, TestValidOrigins.check_valid)


class TestValidPorts(unittest.TestCase):
    def check_valid_port(self, case):
        value, port = case
        parsed = parse_origin(value)
        self.assertTrue(parsed.valid)
        self.assertEqual(parsed.port, port)
        self.assertEqual(parsed.explicit_port, port)


add_matrix_tests(TestValidPorts, "valid_port", VALID_PORTS, TestValidPorts.check_valid_port)


class TestValidIPv4(unittest.TestCase):
    def check_ipv4(self, case):
        parsed = parse_origin(case)
        self.assertTrue(parsed.valid)
        self.assertEqual(parsed.host_type, "ipv4")


add_matrix_tests(TestValidIPv4, "valid_ipv4", VALID_IPV4, TestValidIPv4.check_ipv4)


class TestIPv6Canonical(unittest.TestCase):
    def check_ipv6(self, case):
        value, normalized = case
        parsed = parse_origin(value)
        self.assertTrue(parsed.valid)
        self.assertEqual(parsed.normalized, normalized)
        self.assertEqual(parsed.host_type, "ipv6")


add_matrix_tests(TestIPv6Canonical, "canonical_ipv6", IPV6_CANONICAL, TestIPv6Canonical.check_ipv6)


class TestInvalidTypes(unittest.TestCase):
    def check_type(self, case):
        with self.assertRaises(OriginParseError) as caught:
            parse_origin(case)
        self.assertEqual(caught.exception.code, "CORS_ORIGIN_TYPE")
        self.assertIsNone(try_parse_origin(case))
        with self.assertRaises(OriginParseError):
            normalize_origin(case)


add_matrix_tests(TestInvalidTypes, "invalid_type", INVALID_TYPES, TestInvalidTypes.check_type)


class TestWhitespaceControl(unittest.TestCase):
    def check_whitespace(self, case):
        with self.assertRaises(OriginParseError):
            parse_origin(case)
        self.assertIsNone(try_parse_origin(case))


add_matrix_tests(TestWhitespaceControl, "whitespace_control", WHITESPACE_AND_CONTROL, TestWhitespaceControl.check_whitespace)


class TestNonAscii(unittest.TestCase):
    def check_non_ascii(self, case):
        with self.assertRaises(OriginParseError) as caught:
            parse_origin(case)
        self.assertIn(caught.exception.code, {"CORS_ORIGIN_NON_ASCII", "CORS_ORIGIN_WHITESPACE"})
        self.assertIsNone(try_parse_origin(case))


add_matrix_tests(TestNonAscii, "non_ascii", NON_ASCII, TestNonAscii.check_non_ascii)


class TestStructuralInvalid(unittest.TestCase):
    def check_structure(self, case):
        with self.assertRaises(OriginParseError):
            parse_origin(case)
        self.assertIsNone(try_parse_origin(case))


add_matrix_tests(TestStructuralInvalid, "structural", STRUCTURAL_INVALID, TestStructuralInvalid.check_structure)
add_matrix_tests(TestStructuralInvalid, "invalid_port", INVALID_PORTS, TestStructuralInvalid.check_structure)
add_matrix_tests(TestStructuralInvalid, "invalid_ipv4", INVALID_IPV4, TestStructuralInvalid.check_structure)
add_matrix_tests(TestStructuralInvalid, "invalid_ipv6", INVALID_IPV6, TestStructuralInvalid.check_structure)


class TestOriginSpecificBehavior(unittest.TestCase):
    def test_null_is_valid_opaque_serialization(self):
        parsed = parse_origin("null")
        self.assertTrue(parsed.valid)
        self.assertTrue(parsed.is_null)
        self.assertEqual(parsed.normalized, "null")
        self.assertIsNone(parsed.scheme)
        self.assertIsNone(parsed.host)
        self.assertIsNone(parsed.port)

    def test_mixed_case_null_is_not_opaque_origin(self):
        for value in ("NULL", "Null", " null", "null ", " null "):
            with self.subTest(value=value):
                self.assertIsNone(try_parse_origin(value))

    def test_length_cap_enforced(self):
        label = "a" * 63
        host = ".".join([label] * 5 + ["example.com"])
        self.assertIsNone(try_parse_origin("https://" + host))

    def test_label_length_lower_boundary(self):
        self.assertTrue(parse_origin("https://" + "a" * 63 + ".example.com").valid)

    def test_label_length_upper_boundary_rejected(self):
        self.assertIsNone(try_parse_origin("https://" + "a" * 64 + ".example.com"))

    def test_localhost_domain_forms(self):
        self.assertTrue(parse_origin("https://localhost").is_localhost)
        self.assertTrue(parse_origin("https://app.localhost").is_localhost)

    def test_loopback_ip_forms(self):
        self.assertTrue(parse_origin("https://127.0.0.1").is_localhost)
        self.assertTrue(parse_origin("https://127.255.255.254").is_localhost)
        self.assertTrue(parse_origin("https://[::1]").is_localhost)

    def test_non_loopback_ip_forms(self):
        self.assertFalse(parse_origin("https://128.0.0.1").is_localhost)
        self.assertFalse(parse_origin("https://[::2]").is_localhost)

    def test_parsed_origin_is_frozen(self):
        parsed = parse_origin("https://example.com")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            parsed.host = "evil.example"

    def test_default_port_canonicalization_keeps_explicit_marker(self):
        parsed = parse_origin("https://example.com:443")
        self.assertEqual(parsed.explicit_port, 443)
        self.assertTrue(parsed.is_default_port)
        self.assertEqual(parsed.normalized, "https://example.com")

    def test_normalize_origin_returns_string(self):
        self.assertIsInstance(normalize_origin("HTTPS://EXAMPLE.COM"), str)


if __name__ == "__main__":
    unittest.main()
