"""Framework-agnostic CORS security policy evaluation."""

from __future__ import annotations

import inspect
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping, Optional, Sequence, Tuple

from ._headers import HeaderState, ImmutableHeaders, collect_request_headers, validate_header_name
from .errors import CorsConfigError, CorsInputError
from .origin import (
    MAX_HEADER_NAME_LENGTH,
    MAX_METHOD_LENGTH,
    TOKEN_RE,
    OriginPattern,
    ParsedOrigin,
    _http_scheme_use_allowed,
    is_overbroad_wildcard_base,
    matches_pattern,
    parse_origin,
    parse_origin_pattern,
)

DEFAULT_METHODS = ("GET", "HEAD", "POST")
DEFAULT_MAX_AGE = 600
MAX_MAX_AGE = 86400
DEFAULT_MAX_REQUEST_HEADERS = 32
DEFAULT_MAX_REQUEST_HEADERS_BYTES = 2048
MAX_REQUEST_HEADERS_LIMIT = 128
MAX_REQUEST_HEADER_BYTES_LIMIT = 16384

DANGEROUS_METHODS = frozenset({"TRACE", "CONNECT"})
HARD_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
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
    }
)
BROWSER_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "accept-charset",
        "accept-encoding",
        "cookie",
        "cookie2",
        "date",
        "dnt",
        "expect",
        "referer",
    }
)
FORBIDDEN_EXPOSE_HEADERS = frozenset({"set-cookie", "set-cookie2"})

CORS_RESPONSE_HEADERS = (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-allow-private-network",
)

CONFIG_KEYS = frozenset(
    {
        "allowed_origins",
        "allow_credentials",
        "allowed_methods",
        "allowed_headers",
        "expose_headers",
        "max_age",
        "allow_null_origin",
        "allow_http_localhost",
        "multi_level_subdomains",
        "allow_private_network",
        "allow_origin_predicate",
        "max_request_headers",
        "max_request_headers_bytes",
        "allow_forbidden_headers",
    }
)

_UNSET = object()
_PRINTABLE_ASCII_RE = re.compile(r"\A[\x20-\x7e]*\Z")


@dataclass(frozen=True)
class CorsDecision:
    """Immutable result of one policy evaluation.

    ``status_code`` is 204 for an authorized terminal preflight, 403 for a
    denied terminal preflight, and None for non-preflight requests. A
    non-preflight response is produced by the downstream application; the
    middleware strips or installs CORS headers on that response.
    """

    allowed: bool
    is_preflight: bool
    status_code: Optional[int]
    headers: ImmutableHeaders
    vary: Tuple[str, ...]
    reason: str
    code: str
    origin: Optional[str] = None
    remove_headers: Tuple[str, ...] = CORS_RESPONSE_HEADERS

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", ImmutableHeaders(self.headers))
        object.__setattr__(self, "vary", tuple(self.vary))
        object.__setattr__(self, "remove_headers", tuple(self.remove_headers))


def _config_error(reason: str, value: object, code: str = "CORS_INVALID_TYPE") -> CorsConfigError:
    return CorsConfigError(reason, value, code)


def validate_method(value: object) -> Optional[str]:
    """Return a safe method token or None."""

    if not isinstance(value, str):
        return None
    if len(value) == 0 or len(value) > MAX_METHOD_LENGTH or not TOKEN_RE.match(value):
        return None
    if value == "*" or value.upper() in DANGEROUS_METHODS:
        return None
    return value


def header_is_hard_forbidden(lower: str) -> bool:
    return lower in HARD_FORBIDDEN_REQUEST_HEADERS


def header_is_browser_forbidden(lower: str) -> bool:
    return lower in BROWSER_FORBIDDEN_REQUEST_HEADERS or lower.startswith("sec-") or lower.startswith("proxy-")


def _sequence_option(value: object, key: str) -> Sequence[object]:
    if value is _UNSET:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    raise _config_error(key + " must be a string or a list of strings", value)


def _bool_option(options: Mapping[str, object], key: str, fallback: bool) -> bool:
    value = options.get(key, _UNSET)
    if value is _UNSET:
        return fallback
    if type(value) is not bool:
        raise _config_error(key + " must be exactly true or false", value)
    return value  # type: ignore[return-value]


def _integer_option(
    options: Mapping[str, object],
    key: str,
    fallback: int,
    minimum: int,
    maximum: int,
    code: str = "CORS_INVALID_TYPE",
) -> int:
    value = options.get(key, _UNSET)
    if value is _UNSET:
        return fallback
    if type(value) is not int:
        raise _config_error(key + " must be an integer", value, code)
    if value < minimum or value > maximum:  # type: ignore[operator]
        raise _config_error(
            key + " must be an integer from " + str(minimum) + " through " + str(maximum),
            value,
            code,
        )
    return value  # type: ignore[return-value]


def _normalize_methods(value: object) -> Tuple[str, ...]:
    values = list(DEFAULT_METHODS) if value is _UNSET else list(_sequence_option(value, "allowed_methods"))
    output = []
    seen = set()
    for item in values:
        method = validate_method(item)
        if method is None:
            raise _config_error(
                "allowed_methods entries must be safe RFC 9110 method tokens and must not be TRACE or CONNECT",
                item,
                "CORS_INVALID_METHOD",
            )
        if method not in seen:
            seen.add(method)
            output.append(method)
    if not output:
        raise _config_error("allowed_methods must contain at least one method", value, "CORS_INVALID_METHOD")
    return tuple(output)


def _normalize_allowed_headers(value: object, allow_forbidden_headers: bool) -> Tuple[str, ...]:
    output = []
    seen = set()
    for item in _sequence_option(value, "allowed_headers"):
        lower = validate_header_name(item)
        if lower is None or lower == "*":
            raise _config_error("allowed_headers entries must be legal explicit HTTP header names", item, "CORS_INVALID_HEADER")
        if header_is_hard_forbidden(lower):
            raise _config_error(
                "allowed_headers cannot include protocol, hop-by-hop or CORS control headers",
                item,
                "CORS_UNSAFE_ALLOWED_HEADER",
            )
        if header_is_browser_forbidden(lower) and not allow_forbidden_headers:
            raise _config_error(
                "allowed_headers cannot include browser-forbidden headers without allow_forbidden_headers",
                item,
                "CORS_UNSAFE_ALLOWED_HEADER",
            )
        if lower not in seen:
            seen.add(lower)
            output.append(lower)
    return tuple(output)


def _normalize_expose_headers(value: object) -> Tuple[str, ...]:
    output = []
    seen = set()
    for item in _sequence_option(value, "expose_headers"):
        lower = validate_header_name(item)
        if lower is None or lower == "*":
            raise _config_error("expose_headers entries must be legal explicit HTTP header names", item, "CORS_UNSAFE_EXPOSE_HEADER")
        if lower in FORBIDDEN_EXPOSE_HEADERS:
            raise _config_error("expose_headers cannot expose Set-Cookie response headers", item, "CORS_UNSAFE_EXPOSE_HEADER")
        if lower not in seen:
            seen.add(lower)
            output.append(lower)
    return tuple(output)


def _normalize_origin_entries(value: object, allow_credentials: bool) -> Tuple[OriginPattern, ...]:
    output = []
    seen = set()
    for item in _sequence_option(value, "allowed_origins"):
        if not isinstance(item, str):
            raise _config_error("allowed_origins entries must be strings", item)
        pattern = parse_origin_pattern(item)
        if pattern.type == "any" and allow_credentials:
            raise _config_error(
                "the wildcard * origin can never be combined with credentials",
                item,
                "CORS_WILDCARD_WITH_CREDENTIALS",
            )
        if pattern.type == "subdomain" and is_overbroad_wildcard_base(pattern.host or ""):
            raise _config_error(
                "the subdomain wildcard base is a public suffix or otherwise overbroad",
                item,
                "CORS_OVERBROAD_SUBDOMAIN_WILDCARD",
            )
        if pattern.type == "subdomain" and pattern.scheme == "http":
            raise _config_error(
                "plaintext http subdomain wildcards are never allowed",
                item,
                "CORS_INSECURE_HTTP_ORIGIN",
            )
        if pattern.type == "exact" and pattern.scheme == "http" and not pattern.is_localhost:
            raise _config_error(
                "insecure http origins are rejected except explicit localhost development origins",
                item,
                "CORS_INSECURE_HTTP_ORIGIN",
            )
        key = pattern.type + "|" + pattern.key
        if key not in seen:
            seen.add(key)
            output.append(pattern)
    return tuple(output)


def _unknown_config_keys(options: Mapping[object, object]) -> list:
    unknown = []
    for key in options:
        if not isinstance(key, str) or key not in CONFIG_KEYS:
            unknown.append(key)
    return sorted(unknown, key=repr)


def _normalize_config(options: Mapping[str, object]) -> dict:
    unknown = _unknown_config_keys(options)
    if unknown:
        raise _config_error("unknown policy option " + repr(unknown[0]), unknown[0], "CORS_UNKNOWN_OPTION")

    allow_credentials = _bool_option(options, "allow_credentials", False)
    allow_null_origin = _bool_option(options, "allow_null_origin", False)
    allow_http_localhost = _bool_option(options, "allow_http_localhost", False)
    multi_level_subdomains = _bool_option(options, "multi_level_subdomains", False)
    allow_private_network = _bool_option(options, "allow_private_network", False)
    allow_forbidden_headers = _bool_option(options, "allow_forbidden_headers", False)

    if allow_null_origin and allow_credentials:
        raise _config_error(
            "the null origin can never be allowed when credentials are enabled",
            allow_null_origin,
            "CORS_NULL_ORIGIN_ALLOWED",
        )

    max_age = _integer_option(options, "max_age", DEFAULT_MAX_AGE, 0, MAX_MAX_AGE, "CORS_INVALID_MAX_AGE")
    max_request_headers = _integer_option(
        options,
        "max_request_headers",
        DEFAULT_MAX_REQUEST_HEADERS,
        1,
        MAX_REQUEST_HEADERS_LIMIT,
    )
    max_request_headers_bytes = _integer_option(
        options,
        "max_request_headers_bytes",
        DEFAULT_MAX_REQUEST_HEADERS_BYTES,
        128,
        MAX_REQUEST_HEADER_BYTES_LIMIT,
    )
    methods = _normalize_methods(options.get("allowed_methods", _UNSET))
    allowed_headers = _normalize_allowed_headers(options.get("allowed_headers", _UNSET), allow_forbidden_headers)
    expose_headers = _normalize_expose_headers(options.get("expose_headers", _UNSET))

    predicate = options.get("allow_origin_predicate", None)
    if predicate is not None:
        if not callable(predicate) or inspect.iscoroutinefunction(predicate):
            raise _config_error("allow_origin_predicate must be a synchronous callable", predicate)

    patterns = _normalize_origin_entries(options.get("allowed_origins", _UNSET), allow_credentials)
    if allow_private_network and any(pattern.type == "any" for pattern in patterns):
        raise _config_error(
            "Private Network Access can never be combined with the universal wildcard origin",
            options.get("allowed_origins"),
            "CORS_PRIVATE_NETWORK_WITH_WILDCARD",
        )

    return {
        "allowed_origins": tuple(pattern.key for pattern in patterns),
        "allow_credentials": allow_credentials,
        "allowed_methods": methods,
        "allowed_headers": allowed_headers,
        "expose_headers": expose_headers,
        "max_age": max_age,
        "allow_null_origin": allow_null_origin,
        "allow_http_localhost": allow_http_localhost,
        "multi_level_subdomains": multi_level_subdomains,
        "allow_private_network": allow_private_network,
        "allow_origin_predicate": predicate,
        "max_request_headers": max_request_headers,
        "max_request_headers_bytes": max_request_headers_bytes,
        "allow_forbidden_headers": allow_forbidden_headers,
        "_patterns": patterns,
    }


class CorsPolicy:
    """Immutable framework-independent CORS policy.

    Create instances with ``create_cors_policy`` or ``CorsPolicy.from_dict``.
    Attribute mutation is blocked, and runtime invariants are checked again on
    every evaluation so even reflective object-level tampering fails closed.
    """

    __slots__ = (
        "allowed_origins",
        "allow_credentials",
        "allowed_methods",
        "allowed_headers",
        "expose_headers",
        "max_age",
        "allow_null_origin",
        "allow_http_localhost",
        "multi_level_subdomains",
        "allow_private_network",
        "allow_origin_predicate",
        "max_request_headers",
        "max_request_headers_bytes",
        "allow_forbidden_headers",
        "_patterns",
    )

    def __init__(
        self,
        *,
        allowed_origins: object = _UNSET,
        allow_credentials: object = _UNSET,
        allowed_methods: object = _UNSET,
        allowed_headers: object = _UNSET,
        expose_headers: object = _UNSET,
        max_age: object = _UNSET,
        allow_null_origin: object = _UNSET,
        allow_http_localhost: object = _UNSET,
        multi_level_subdomains: object = _UNSET,
        allow_private_network: object = _UNSET,
        allow_origin_predicate: object = None,
        max_request_headers: object = _UNSET,
        max_request_headers_bytes: object = _UNSET,
        allow_forbidden_headers: object = _UNSET,
    ) -> None:
        raw = {}
        for key, value in (
            ("allowed_origins", allowed_origins),
            ("allow_credentials", allow_credentials),
            ("allowed_methods", allowed_methods),
            ("allowed_headers", allowed_headers),
            ("expose_headers", expose_headers),
            ("max_age", max_age),
            ("allow_null_origin", allow_null_origin),
            ("allow_http_localhost", allow_http_localhost),
            ("multi_level_subdomains", multi_level_subdomains),
            ("allow_private_network", allow_private_network),
            ("max_request_headers", max_request_headers),
            ("max_request_headers_bytes", max_request_headers_bytes),
            ("allow_forbidden_headers", allow_forbidden_headers),
        ):
            if value is not _UNSET:
                raw[key] = value
        if allow_origin_predicate is not None:
            raw["allow_origin_predicate"] = allow_origin_predicate
        normalized = _normalize_config(raw)
        for key, value in normalized.items():
            object.__setattr__(self, key, value)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("CorsPolicy is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("CorsPolicy is immutable")

    def __repr__(self) -> str:
        return "CorsPolicy(allowed_origins=" + repr(self.allowed_origins) + ", allow_credentials=" + repr(self.allow_credentials) + ")"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CorsPolicy):
            return False
        return self._comparison_tuple() == other._comparison_tuple()

    def _comparison_tuple(self) -> tuple:
        return (
            self.allowed_origins,
            self.allow_credentials,
            self.allowed_methods,
            self.allowed_headers,
            self.expose_headers,
            self.max_age,
            self.allow_null_origin,
            self.allow_http_localhost,
            self.multi_level_subdomains,
            self.allow_private_network,
            self.allow_origin_predicate,
            self.max_request_headers,
            self.max_request_headers_bytes,
            self.allow_forbidden_headers,
        )

    @classmethod
    def from_dict(cls, config: Mapping[str, object]) -> "CorsPolicy":
        """Create a policy from a plain mapping such as decoded JSON."""

        if not isinstance(config, Mapping):
            raise _config_error("policy configuration must be a mapping", config)
        copied = dict(config)
        unknown = _unknown_config_keys(copied)
        if unknown:
            raise _config_error("unknown policy option " + repr(unknown[0]), unknown[0], "CORS_UNKNOWN_OPTION")
        return cls(**copied)

    @property
    def config(self) -> Mapping[str, object]:
        """Immutable public view of normalized non-secret configuration."""

        return MappingProxyType(
            {
                "allowed_origins": self.allowed_origins,
                "allow_credentials": self.allow_credentials,
                "allowed_methods": self.allowed_methods,
                "allowed_headers": self.allowed_headers,
                "expose_headers": self.expose_headers,
                "max_age": self.max_age,
                "allow_null_origin": self.allow_null_origin,
                "allow_http_localhost": self.allow_http_localhost,
                "multi_level_subdomains": self.multi_level_subdomains,
                "allow_private_network": self.allow_private_network,
                "max_request_headers": self.max_request_headers,
                "max_request_headers_bytes": self.max_request_headers_bytes,
                "allow_forbidden_headers": self.allow_forbidden_headers,
                "has_origin_predicate": self.allow_origin_predicate is not None,
            }
        )

    def _check_runtime_invariants(self) -> None:
        if type(self.allow_credentials) is not bool or type(self.allow_private_network) is not bool:
            raise _config_error("policy boolean invariants were violated", None)
        patterns = getattr(self, "_patterns", ())
        if self.allow_credentials and (
            self.allow_null_origin or any(pattern.type == "any" for pattern in patterns)
        ):
            raise _config_error(
                "credentials can never be combined with the null or universal wildcard origin",
                None,
                "CORS_WILDCARD_WITH_CREDENTIALS",
            )
        if self.allow_private_network and any(pattern.type == "any" for pattern in patterns):
            raise _config_error(
                "Private Network Access can never be combined with the universal wildcard origin",
                None,
                "CORS_PRIVATE_NETWORK_WITH_WILDCARD",
            )

    def _authorize_origin(self, parsed: ParsedOrigin) -> Tuple[bool, str, str, bool]:
        if parsed.is_null:
            if not self.allow_null_origin:
                return False, "CORS_NULL_ORIGIN", "the null origin is blocked by default", False
            if self.allow_credentials:
                return False, "CORS_NULL_ORIGIN_WITH_CREDENTIALS", "the null origin can never use credentials", False
            return True, "CORS_ORIGIN_ALLOWED", "the explicitly configured null origin is allowed", False

        matched = None  # type: Optional[OriginPattern]
        universal = None  # type: Optional[OriginPattern]
        for pattern in self._patterns:
            if not matches_pattern(parsed, pattern, self.multi_level_subdomains):
                continue
            if pattern.type == "any":
                if universal is None:
                    universal = pattern
            else:
                matched = pattern
                break
        if matched is None:
            matched = universal
        if matched is not None:
            if not _http_scheme_use_allowed(self.allow_http_localhost, parsed, matched):
                return (
                    False,
                    "CORS_INSECURE_HTTP_ORIGIN",
                    "insecure http is limited to explicit localhost development use",
                    False,
                )
            return True, "CORS_ORIGIN_ALLOWED", "the origin matches the configured allowlist", matched.type == "any"

        if self.allow_origin_predicate is not None:
            scheme_allowed = parsed.scheme == "https" or (
                parsed.scheme == "http" and parsed.is_localhost and self.allow_http_localhost
            )
            if scheme_allowed:
                try:
                    predicate_result = self.allow_origin_predicate(parsed)
                except Exception:
                    predicate_result = False
                if type(predicate_result) is bool:
                    if predicate_result:
                        return True, "CORS_ORIGIN_ALLOWED", "the synchronous origin predicate authorized the origin", False
                else:
                    return (
                        False,
                        "CORS_PREDICATE_INVALID_RESULT",
                        "the origin predicate did not return exactly true or false",
                        False,
                    )

        return False, "CORS_ORIGIN_NOT_ALLOWED", "the origin does not match the configured allowlist", False

    def _parse_requested_headers(self, state: HeaderState) -> Tuple[bool, Tuple[str, ...], str]:
        if not state.present:
            return True, (), ""
        if not state.valid or state.value is None:
            return False, (), "Access-Control-Request-Headers must be a single string header value"
        raw = state.value
        if not _PRINTABLE_ASCII_RE.match(raw):
            return False, (), "Access-Control-Request-Headers contains control or non-ASCII characters"
        if len(raw.encode("ascii")) > self.max_request_headers_bytes:
            return False, (), "Access-Control-Request-Headers exceeds the configured byte cap"
        pieces = raw.split(",")
        if len(pieces) > self.max_request_headers:
            return False, (), "Access-Control-Request-Headers exceeds the configured count cap"
        output = []
        seen = set()
        for piece in pieces:
            trimmed = piece.strip(" \t")
            if trimmed == "":
                return False, (), "Access-Control-Request-Headers contains an empty header name"
            lower = validate_header_name(trimmed)
            if lower is None or lower == "*":
                return False, (), "Access-Control-Request-Headers contains a prohibited header token"
            if lower not in seen:
                seen.add(lower)
                output.append(lower)
        if len(output) > self.max_request_headers:
            return False, (), "Access-Control-Request-Headers exceeds the configured count cap"
        return True, tuple(output), ""

    def _validate_preflight(self, parsed: ParsedOrigin, request_headers: object) -> Tuple[bool, str, str, Optional[str], Tuple[str, ...], bool]:
        method_state = request_headers.state("access-control-request-method")
        if not method_state.present or not method_state.valid or method_state.value is None:
            return (
                False,
                "CORS_PREFLIGHT_METHOD_MALFORMED",
                "the preflight method header is missing, repeated or not a string",
                None,
                (),
                False,
            )
        requested_method = method_state.value
        if validate_method(requested_method) is None or "," in requested_method:
            return (
                False,
                "CORS_PREFLIGHT_METHOD_MALFORMED",
                "the requested method is not a single safe RFC 9110 token",
                None,
                (),
                False,
            )
        if requested_method not in self.allowed_methods:
            return (
                False,
                "CORS_METHOD_NOT_ALLOWED",
                "the requested method is not in the policy allowlist",
                None,
                (),
                False,
            )

        headers_valid, requested_headers, header_reason = self._parse_requested_headers(
            request_headers.state("access-control-request-headers")
        )
        if not headers_valid:
            return False, "CORS_HEADERS_MALFORMED", header_reason, None, (), False
        for header in requested_headers:
            if header not in self.allowed_headers:
                return (
                    False,
                    "CORS_HEADERS_NOT_ALLOWED",
                    "a requested header is not in the policy allowlist",
                    None,
                    (),
                    False,
                )

        private_state = request_headers.state("access-control-request-private-network")
        private_requested = False
        if private_state.present:
            if not private_state.valid or private_state.value != "true" or "," in private_state.value:
                return (
                    False,
                    "CORS_PRIVATE_NETWORK_MALFORMED",
                    "the private network request header must be the single value true",
                    None,
                    (),
                    False,
                )
            private_requested = True
            if not self.allow_private_network or parsed.is_null:
                return (
                    False,
                    "CORS_PRIVATE_NETWORK_DENIED",
                    "private network access is denied by default or for an opaque origin",
                    None,
                    (),
                    False,
                )
        return True, "", "", requested_method, requested_headers, private_requested

    @staticmethod
    def _base_vary(is_preflight: bool) -> Tuple[str, ...]:
        if not is_preflight:
            return ("Origin",)
        return (
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "Access-Control-Request-Private-Network",
        )

    @staticmethod
    def _deny(is_preflight: bool, code: str, reason: str, origin: Optional[str]) -> CorsDecision:
        return CorsDecision(
            allowed=False,
            is_preflight=is_preflight,
            status_code=403 if is_preflight else None,
            headers=ImmutableHeaders(),
            vary=CorsPolicy._base_vary(is_preflight),
            reason=reason,
            code=code,
            origin=origin,
        )

    def _cors_response_headers(
        self,
        parsed: ParsedOrigin,
        wildcard: bool,
        preflight: Optional[Tuple[str, Tuple[str, ...], bool]],
    ) -> ImmutableHeaders:
        values = {}
        values["Access-Control-Allow-Origin"] = "*" if wildcard else parsed.normalized
        if self.allow_credentials:
            values["Access-Control-Allow-Credentials"] = "true"
        if preflight is None:
            if self.expose_headers:
                values["Access-Control-Expose-Headers"] = ", ".join(self.expose_headers)
            return ImmutableHeaders(values)
        method, request_headers, private_requested = preflight
        values["Access-Control-Allow-Methods"] = method
        if request_headers:
            values["Access-Control-Allow-Headers"] = ", ".join(request_headers)
        values["Access-Control-Max-Age"] = str(self.max_age)
        if private_requested:
            values["Access-Control-Allow-Private-Network"] = "true"
        return ImmutableHeaders(values)

    def evaluate(self, method: str, headers: object) -> CorsDecision:
        """Evaluate one request method and header collection.

        ``headers`` may be a mapping or an iterable of pairs. Repeated Origin
        and preflight control headers fail closed. Malformed requests never
        raise for attacker-controlled input; they return a denied decision.
        """

        self._check_runtime_invariants()
        request_headers = collect_request_headers(headers)
        origin_state = request_headers.state("origin")
        acrm_state = request_headers.state("access-control-request-method")
        is_preflight = method == "OPTIONS" and origin_state.present and acrm_state.present

        if not isinstance(method, str) or validate_method(method) is None:
            return self._deny(False, "CORS_METHOD_MALFORMED", "the request method is not a safe RFC 9110 token", None)
        if request_headers.malformed:
            return self._deny(is_preflight, "CORS_HEADERS_MALFORMED", "the request headers are malformed", None)

        if not origin_state.present:
            return CorsDecision(
                allowed=False,
                is_preflight=False,
                status_code=None,
                headers=ImmutableHeaders(),
                vary=self._base_vary(False),
                reason="the request has no Origin header and is not a CORS request",
                code="CORS_NO_ORIGIN",
                origin=None,
            )
        if not origin_state.valid or origin_state.value is None:
            return self._deny(is_preflight, "CORS_ORIGIN_MALFORMED", "the Origin header is repeated or not a string", None)

        try:
            parsed = parse_origin(origin_state.value)
        except Exception as exc:
            code = getattr(exc, "code", "CORS_ORIGIN_MALFORMED")
            reason = getattr(exc, "reason", "the Origin header is malformed")
            return self._deny(is_preflight, code, reason, None)

        allowed, code, reason, wildcard = self._authorize_origin(parsed)
        if not allowed:
            return self._deny(is_preflight, code, reason, parsed.normalized)

        if not is_preflight:
            return CorsDecision(
                allowed=True,
                is_preflight=False,
                status_code=None,
                headers=self._cors_response_headers(parsed, wildcard, None),
                vary=self._base_vary(False),
                reason=reason,
                code=code,
                origin=parsed.normalized,
            )

        valid, preflight_code, preflight_reason, request_method, requested_headers, private_requested = self._validate_preflight(
            parsed, request_headers
        )
        if not valid:
            return self._deny(True, preflight_code, preflight_reason, parsed.normalized)
        return CorsDecision(
            allowed=True,
            is_preflight=True,
            status_code=204,
            headers=self._cors_response_headers(parsed, wildcard, (request_method or "", requested_headers, private_requested)),
            vary=self._base_vary(True),
            reason="the preflight request is authorized",
            code="CORS_PREFLIGHT_ALLOWED",
            origin=parsed.normalized,
        )

    def is_origin_allowed(self, origin: str) -> bool:
        """Return whether one origin serialization is authorized."""

        self._check_runtime_invariants()
        try:
            parsed = parse_origin(origin)
        except Exception:
            return False
        return self._authorize_origin(parsed)[0]

    def match(self, origin: str) -> bool:
        """Alias for is_origin_allowed."""

        return self.is_origin_allowed(origin)


def create_cors_policy(
    *,
    allowed_origins: object = _UNSET,
    allow_credentials: object = _UNSET,
    allowed_methods: object = _UNSET,
    allowed_headers: object = _UNSET,
    expose_headers: object = _UNSET,
    max_age: object = _UNSET,
    allow_null_origin: object = _UNSET,
    allow_http_localhost: object = _UNSET,
    multi_level_subdomains: object = _UNSET,
    allow_private_network: object = _UNSET,
    allow_origin_predicate: object = None,
    max_request_headers: object = _UNSET,
    max_request_headers_bytes: object = _UNSET,
    allow_forbidden_headers: object = _UNSET,
) -> CorsPolicy:
    """Create a validated immutable CORS policy."""

    return CorsPolicy(
        allowed_origins=allowed_origins,
        allow_credentials=allow_credentials,
        allowed_methods=allowed_methods,
        allowed_headers=allowed_headers,
        expose_headers=expose_headers,
        max_age=max_age,
        allow_null_origin=allow_null_origin,
        allow_http_localhost=allow_http_localhost,
        multi_level_subdomains=multi_level_subdomains,
        allow_private_network=allow_private_network,
        allow_origin_predicate=allow_origin_predicate,
        max_request_headers=max_request_headers,
        max_request_headers_bytes=max_request_headers_bytes,
        allow_forbidden_headers=allow_forbidden_headers,
    )


__all__ = [
    "BROWSER_FORBIDDEN_REQUEST_HEADERS",
    "CONFIG_KEYS",
    "CORS_RESPONSE_HEADERS",
    "CorsDecision",
    "CorsPolicy",
    "DANGEROUS_METHODS",
    "DEFAULT_MAX_AGE",
    "DEFAULT_MAX_REQUEST_HEADERS",
    "DEFAULT_MAX_REQUEST_HEADERS_BYTES",
    "DEFAULT_METHODS",
    "FORBIDDEN_EXPOSE_HEADERS",
    "HARD_FORBIDDEN_REQUEST_HEADERS",
    "MAX_MAX_AGE",
    "MAX_REQUEST_HEADERS_LIMIT",
    "MAX_REQUEST_HEADER_BYTES_LIMIT",
    "create_cors_policy",
    "header_is_browser_forbidden",
    "header_is_hard_forbidden",
    "validate_method",
]
