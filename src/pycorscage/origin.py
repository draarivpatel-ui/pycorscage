"""Strict serialized-origin parsing, canonicalization, and matching."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional, Sequence, Tuple

from .errors import CorsConfigError, CorsInputError, OriginParseError

MAX_ORIGIN_LENGTH = 320
MAX_METHOD_LENGTH = 64
MAX_HEADER_NAME_LENGTH = 128
DEFAULT_PORTS = {"http": 80, "https": 443}

TOKEN_RE = re.compile(r"\A[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
VISIBLE_ASCII_RE = re.compile(r"\A[!-~]+\Z")
SCHEME_AUTHORITY_RE = re.compile(r"\A([A-Za-z][A-Za-z0-9+.-]*)://(.*)\Z")
DOMAIN_LABEL_RE = re.compile(r"\A[a-z0-9-]+\Z")
NUMERIC_HOST_RE = re.compile(r"\A[0-9.]+\Z")
DIGITS_RE = re.compile(r"\A[0-9]+\Z")
HEX_GROUP_RE = re.compile(r"\A[0-9a-fA-F]{1,4}\Z")

PUBLIC_SUFFIX_AGGREGATORS = frozenset(
    {
        "ac",
        "co",
        "com",
        "edu",
        "go",
        "gob",
        "gov",
        "mil",
        "ne",
        "net",
        "or",
        "org",
        "sch",
    }
)

KNOWN_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.uk",
        "gov.uk",
        "ltd.uk",
        "me.uk",
        "net.uk",
        "nhs.uk",
        "org.uk",
        "plc.uk",
        "police.uk",
        "sch.uk",
        "com.au",
        "edu.au",
        "gov.au",
        "net.au",
        "org.au",
        "co.jp",
        "ac.jp",
        "go.jp",
        "ne.jp",
        "or.jp",
        "com.cn",
        "edu.cn",
        "gov.cn",
        "net.cn",
        "org.cn",
        "com.br",
        "net.br",
        "org.br",
        "com.mx",
        "org.mx",
        "gob.mx",
        "co.nz",
        "org.nz",
        "net.nz",
        "ac.nz",
        "govt.nz",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
        "com.sg",
        "net.sg",
        "org.sg",
        "gov.sg",
        "com.hk",
        "net.hk",
        "org.hk",
        "gov.hk",
        "co.kr",
        "ne.kr",
        "or.kr",
        "go.kr",
        "com.tw",
        "org.tw",
        "net.tw",
        "com.tr",
        "org.tr",
        "net.tr",
        "github.io",
        "gitlab.io",
        "pages.dev",
        "vercel.app",
        "netlify.app",
        "herokuapp.com",
        "azurewebsites.net",
        "cloudfront.net",
        "workers.dev",
        "web.app",
        "firebaseapp.com",
        "appspot.com",
        "amazonaws.com",
    }
)


@dataclass(frozen=True)
class ParsedOrigin:
    """Canonical parsed representation of one serialized origin."""

    valid: bool
    is_null: bool
    normalized: str
    scheme: Optional[str]
    host: Optional[str]
    port: Optional[int]
    explicit_port: Optional[int]
    is_default_port: bool
    host_type: Optional[str]
    is_localhost: bool


@dataclass(frozen=True)
class OriginPattern:
    """Compiled allowlist entry used internally and by match_origin."""

    type: str
    key: str
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    is_localhost: bool = False


@dataclass(frozen=True)
class _Authority:
    host: str
    host_type: str
    labels: Tuple[str, ...]
    explicit_port: Optional[int]


def _invalid(code: str, reason: str, value: object) -> OriginParseError:
    return OriginParseError(code, reason, value)


def _parse_port_text(text: Optional[str], original: object) -> Tuple[bool, Optional[int], Optional[str]]:
    if text is None:
        return True, None, None
    if text == "":
        return False, None, "the port is empty"
    if not DIGITS_RE.match(text):
        return False, None, "the port contains non-digits"
    if len(text) > 1 and text.startswith("0"):
        return False, None, "the port has a leading zero"
    if len(text) > 5:
        return False, None, "the port is too long"
    port = int(text)
    if port < 1 or port > 65535:
        return False, None, "the port is outside 1 through 65535"
    return True, port, None


def _parse_ipv4_parts(text: str) -> Optional[Tuple[int, int, int, int]]:
    pieces = text.split(".")
    if len(pieces) != 4:
        return None
    output = []
    for piece in pieces:
        if not re.match(r"\A[0-9]{1,3}\Z", piece):
            return None
        if len(piece) > 1 and piece.startswith("0"):
            return None
        value = int(piece)
        if value > 255:
            return None
        output.append(value)
    return output[0], output[1], output[2], output[3]


def _ipv4_number_lenient(text: str) -> Optional[int]:
    if text == "":
        return None
    if text.startswith(("0x", "0X")):
        rest = text[2:]
        if rest == "":
            return 0
        if not re.match(r"\A[0-9a-fA-F]+\Z", rest):
            return None
        return int(rest, 16)
    if len(text) > 1 and text.startswith("0"):
        if not re.match(r"\A[0-7]+\Z", text):
            return None
        return int(text, 8)
    if not DIGITS_RE.match(text):
        return None
    return int(text)


def _normalize_domain_or_ipv4(host: str) -> Tuple[bool, str, str, Tuple[str, ...], str]:
    if host == "":
        return False, "", "", (), "the host is empty"
    if len(host) > 253:
        return False, "", "", (), "the host is too long"
    lower = host.lower()
    if lower.endswith("."):
        return False, "", "", (), "a trailing root dot is not accepted"
    labels = lower.split(".")
    for label in labels:
        if label == "":
            return False, "", "", (), "the host contains an empty label"
        if len(label) > 63:
            return False, "", "", (), "a host label is too long"
        if not DOMAIN_LABEL_RE.match(label):
            return False, "", "", (), "a host label contains a prohibited character"
        if label.startswith("-") or label.endswith("-"):
            return False, "", "", (), "a host label starts or ends with a hyphen"

    final_label = labels[-1]
    numericish_final = DIGITS_RE.match(final_label) is not None or _ipv4_number_lenient(final_label) is not None
    browser_would_parse_ipv4 = NUMERIC_HOST_RE.match(lower) is not None or numericish_final
    if browser_would_parse_ipv4:
        ipv4 = _parse_ipv4_parts(lower)
        if ipv4 is None:
            return False, "", "", (), "the IPv4 literal is malformed or obfuscated"
        return True, ".".join(str(part) for part in ipv4), "ipv4", tuple(labels), ""
    return True, lower, "domain", tuple(labels), ""


def _canonical_ipv6(address: ipaddress.IPv6Address) -> str:
    packed = address.packed
    pieces = [(packed[index] << 8) | packed[index + 1] for index in range(0, 16, 2)]
    best_start = -1
    best_length = 0
    index = 0
    while index < len(pieces):
        if pieces[index] != 0:
            index += 1
            continue
        end = index
        while end < len(pieces) and pieces[end] == 0:
            end += 1
        length = end - index
        if length > best_length:
            best_start = index
            best_length = length
        index = end

    rendered = [format(piece, "x") for piece in pieces]
    if best_length < 2:
        return ":".join(rendered)
    left = ":".join(rendered[:best_start])
    right = ":".join(rendered[best_start + best_length :])
    if left and right:
        return left + "::" + right
    if left:
        return left + "::"
    if right:
        return "::" + right
    return "::"


def _parse_authority(authority: str) -> Tuple[bool, Optional[_Authority], str]:
    if authority == "":
        return False, None, "the host is empty"
    if "@" in authority:
        return False, None, "userinfo is prohibited in an origin"
    if "%" in authority:
        return False, None, "percent encoding is prohibited in an origin"
    if "/" in authority or "\\" in authority or "?" in authority or "#" in authority:
        return False, None, "an origin must not contain a path, query, fragment or backslash"

    host_text = ""
    port_text = None  # type: Optional[str]
    if authority.startswith("["):
        closing = authority.find("]")
        if closing == -1:
            return False, None, "the IPv6 literal is missing a closing bracket"
        host_text = authority[1:closing]
        remainder = authority[closing + 1 :]
        if remainder == "":
            port_text = None
        elif remainder.startswith(":"):
            port_text = remainder[1:]
        else:
            return False, None, "unexpected text after the IPv6 literal"
        if host_text == "" or len(host_text) > 45:
            return False, None, "the IPv6 literal is malformed"
        if not re.match(r"\A[0-9a-fA-F:.]+\Z", host_text):
            return False, None, "the IPv6 literal is malformed"
        try:
            address = ipaddress.IPv6Address(host_text)
        except ValueError:
            return False, None, "the IPv6 literal is malformed"
        serialized = "[" + _canonical_ipv6(address) + "]"
        port_valid, explicit_port, port_reason = _parse_port_text(port_text, authority)
        if not port_valid:
            return False, None, port_reason or "the port is malformed"
        return True, _Authority(serialized, "ipv6", (), explicit_port), ""

    if "[" in authority or "]" in authority:
        return False, None, "IPv6 literals must be bracketed"
    colon_count = authority.count(":")
    if colon_count > 1:
        return False, None, "an IPv6 literal must be bracketed"
    if colon_count == 1:
        index = authority.rfind(":")
        host_text = authority[:index]
        port_text = authority[index + 1 :]
    else:
        host_text = authority

    host_valid, host, host_type, labels, host_reason = _normalize_domain_or_ipv4(host_text)
    if not host_valid:
        return False, None, host_reason
    port_valid, explicit_port, port_reason = _parse_port_text(port_text, authority)
    if not port_valid:
        return False, None, port_reason or "the port is malformed"
    return True, _Authority(host, host_type, labels, explicit_port), ""


def _split_scheme_authority(value: str) -> Optional[Tuple[str, str]]:
    match = SCHEME_AUTHORITY_RE.match(value)
    if match is None:
        return None
    return match.group(1).lower(), match.group(2)


def is_localhost_part(host: Optional[str], host_type: Optional[str]) -> bool:
    """Return whether a canonical host is a loopback or localhost name."""

    if host is None or host_type is None:
        return False
    if host_type == "ipv4":
        return host.startswith("127.")
    if host_type == "ipv6":
        return host == "[::1]"
    return host == "localhost" or host.endswith(".localhost")


def parse_origin(value: str) -> ParsedOrigin:
    """Parse and canonicalize one serialized origin.

    Raises ``OriginParseError`` for malformed input. The exact lowercase string
    ``null`` is the opaque origin serialization and returns a valid object with
    ``is_null`` true; policy evaluation still denies it unless explicitly
    enabled without credentials.
    """

    if not isinstance(value, str):
        raise _invalid("CORS_ORIGIN_TYPE", "the origin must be a string", value)
    if value == "":
        raise _invalid("CORS_ORIGIN_EMPTY", "the origin is empty", value)
    if len(value) > MAX_ORIGIN_LENGTH:
        raise _invalid("CORS_ORIGIN_TOO_LONG", "the origin exceeds the strict length cap", value)
    if value != value.strip():
        raise _invalid("CORS_ORIGIN_WHITESPACE", "the origin has leading or trailing whitespace", value)
    if not VISIBLE_ASCII_RE.match(value):
        raise _invalid(
            "CORS_ORIGIN_NON_ASCII",
            "the origin contains whitespace, control or non-ASCII characters",
            value,
        )
    if value == "null":
        return ParsedOrigin(
            valid=True,
            is_null=True,
            normalized="null",
            scheme=None,
            host=None,
            port=None,
            explicit_port=None,
            is_default_port=False,
            host_type=None,
            is_localhost=False,
        )
    if "," in value:
        raise _invalid("CORS_ORIGIN_MULTIPLE", "multiple comma-separated origins are prohibited", value)
    split = _split_scheme_authority(value)
    if split is None:
        raise _invalid("CORS_ORIGIN_MALFORMED", "the origin must use scheme://host form", value)
    scheme, authority_text = split
    if scheme not in DEFAULT_PORTS:
        raise _invalid("CORS_ORIGIN_SCHEME", "only http and https origins are supported", value)
    if authority_text == "":
        raise _invalid("CORS_ORIGIN_HOST_EMPTY", "the origin host is empty", value)
    valid, authority, reason = _parse_authority(authority_text)
    if not valid or authority is None:
        raise _invalid("CORS_ORIGIN_MALFORMED", reason, value)

    default_port = DEFAULT_PORTS[scheme]
    explicit_port = authority.explicit_port
    effective_port = default_port if explicit_port is None else explicit_port
    is_default_port = effective_port == default_port
    serialized_port = ""
    if explicit_port is not None and not is_default_port:
        serialized_port = ":" + str(explicit_port)
    normalized = scheme + "://" + authority.host + serialized_port
    return ParsedOrigin(
        valid=True,
        is_null=False,
        normalized=normalized,
        scheme=scheme,
        host=authority.host,
        port=effective_port,
        explicit_port=explicit_port,
        is_default_port=is_default_port,
        host_type=authority.host_type,
        is_localhost=is_localhost_part(authority.host, authority.host_type),
    )


def try_parse_origin(value: object) -> Optional[ParsedOrigin]:
    """Return a parsed origin or None without raising."""

    try:
        if not isinstance(value, str):
            return None
        return parse_origin(value)
    except OriginParseError:
        return None


def normalize_origin(value: str) -> str:
    """Return the canonical serialization of one valid origin."""

    return parse_origin(value).normalized


def parse_origin_pattern(value: str) -> OriginPattern:
    """Compile one allowlist origin pattern.

    This is exported for advanced validation but most callers should use
    ``create_cors_policy`` or ``match_origin``.
    """

    if not isinstance(value, str) or value == "":
        raise CorsConfigError("an origin entry must be a non-empty string", value, "CORS_INVALID_ORIGIN")
    if value == "*":
        return OriginPattern("any", "*")
    if value == "null":
        raise CorsConfigError("the null origin is controlled only by allow_null_origin", value, "CORS_INVALID_ORIGIN")
    wildcard_count = value.count("*")
    if wildcard_count == 0:
        try:
            exact = parse_origin(value)
        except OriginParseError as exc:
            raise CorsConfigError("the exact origin is malformed: " + exc.reason, value, "CORS_INVALID_ORIGIN") from exc
        if exact.is_null:
            raise CorsConfigError("the null origin is controlled only by allow_null_origin", value, "CORS_INVALID_ORIGIN")
        return OriginPattern(
            "exact",
            exact.normalized,
            exact.scheme,
            exact.host,
            exact.port,
            exact.is_localhost,
        )
    if wildcard_count != 1:
        raise CorsConfigError("only one subdomain wildcard marker is permitted", value, "CORS_INVALID_ORIGIN")
    split = _split_scheme_authority(value)
    if split is None:
        raise CorsConfigError("a wildcard origin must use scheme://host form", value, "CORS_INVALID_ORIGIN")
    scheme, authority_text = split
    if scheme not in DEFAULT_PORTS:
        raise CorsConfigError("only http and https wildcard origins are supported", value, "CORS_INVALID_ORIGIN")
    if not authority_text.startswith("*."):
        raise CorsConfigError("the wildcard must replace the complete leftmost host label", value, "CORS_INVALID_ORIGIN")
    if "*" in authority_text[2:]:
        raise CorsConfigError("the wildcard may only appear as the leftmost host label", value, "CORS_INVALID_ORIGIN")
    base_authority = authority_text[2:]
    if base_authority == "":
        raise CorsConfigError("the wildcard base host is empty", value, "CORS_INVALID_ORIGIN")
    valid, authority, reason = _parse_authority(base_authority)
    if not valid or authority is None:
        raise CorsConfigError("the wildcard base is malformed: " + reason, value, "CORS_INVALID_ORIGIN")
    if authority.host_type != "domain":
        raise CorsConfigError("wildcards are valid only before domain names", value, "CORS_INVALID_ORIGIN")

    default_port = DEFAULT_PORTS[scheme]
    explicit_port = authority.explicit_port
    effective_port = default_port if explicit_port is None else explicit_port
    serialized_port = ""
    if explicit_port is not None and effective_port != default_port:
        serialized_port = ":" + str(explicit_port)
    key = scheme + "://*." + authority.host + serialized_port
    return OriginPattern(
        "subdomain",
        key,
        scheme,
        authority.host,
        effective_port,
        is_localhost_part(authority.host, "domain"),
    )


def is_overbroad_wildcard_base(host: str) -> bool:
    """Conservatively identify public-suffix or otherwise overbroad bases."""

    labels = host.split(".")
    if len(labels) < 2:
        return True
    joined = ".".join(labels)
    if joined in KNOWN_PUBLIC_SUFFIXES:
        return True
    final_label = labels[-1]
    previous_label = labels[-2]
    if len(labels) == 2 and len(final_label) == 2 and previous_label in PUBLIC_SUFFIX_AGGREGATORS:
        return True
    if host == "localhost":
        return True
    return False


def matches_pattern(parsed: ParsedOrigin, pattern: OriginPattern, multi_level_subdomains: bool = False) -> bool:
    """Return whether a parsed origin matches one compiled pattern."""

    if not parsed.valid or parsed.is_null:
        return False
    if pattern.type == "any":
        return True
    if pattern.type == "exact":
        return parsed.normalized == pattern.key
    if parsed.scheme != pattern.scheme or parsed.port != pattern.port:
        return False
    if parsed.host_type != "domain" or parsed.host is None or pattern.host is None:
        return False
    suffix = "." + pattern.host
    if not parsed.host.endswith(suffix):
        return False
    prefix = parsed.host[: len(parsed.host) - len(suffix)]
    if prefix == "":
        return False
    labels = prefix.split(".")
    if not multi_level_subdomains and len(labels) != 1:
        return False
    return all(label != "" for label in labels)


def _http_scheme_use_allowed(
    allow_http_localhost: bool,
    parsed: ParsedOrigin,
    pattern: Optional[OriginPattern],
) -> bool:
    if parsed.scheme == "https":
        return True
    if parsed.scheme != "http" or not parsed.is_localhost:
        return False
    if allow_http_localhost:
        return True
    return bool(
        pattern is not None
        and pattern.type == "exact"
        and pattern.scheme == "http"
        and pattern.is_localhost
    )


def match_origin(
    candidate: str,
    pattern: str,
    *,
    multi_level_subdomains: bool = False,
    allow_http_localhost: bool = False,
) -> bool:
    """Return whether one candidate origin matches one allowlist pattern.

    Invalid candidates and invalid patterns return False. The production
    scheme floor is applied here too: non-local plaintext HTTP never matches,
    and localhost HTTP requires either an exact localhost pattern or the
    explicit ``allow_http_localhost`` development opt-in.
    """

    if type(multi_level_subdomains) is not bool or type(allow_http_localhost) is not bool:
        raise CorsInputError("match_origin boolean options must be booleans")
    parsed = try_parse_origin(candidate)
    if parsed is None or parsed.is_null:
        return False
    try:
        compiled = parse_origin_pattern(pattern)
    except (CorsConfigError, OriginParseError):
        return False
    if compiled.type == "subdomain":
        if compiled.scheme == "http" or is_overbroad_wildcard_base(compiled.host or ""):
            return False
    if not matches_pattern(parsed, compiled, multi_level_subdomains):
        return False
    return _http_scheme_use_allowed(allow_http_localhost, parsed, compiled)


__all__ = [
    "DEFAULT_PORTS",
    "KNOWN_PUBLIC_SUFFIXES",
    "MAX_HEADER_NAME_LENGTH",
    "MAX_METHOD_LENGTH",
    "MAX_ORIGIN_LENGTH",
    "OriginPattern",
    "ParsedOrigin",
    "TOKEN_RE",
    "is_localhost_part",
    "is_overbroad_wildcard_base",
    "match_origin",
    "matches_pattern",
    "normalize_origin",
    "parse_origin",
    "parse_origin_pattern",
    "try_parse_origin",
]
