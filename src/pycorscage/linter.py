"""Structured static auditor for CORS policy configuration mappings."""

from __future__ import annotations

import inspect
from collections.abc import Mapping
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ._headers import validate_header_name
from .errors import CorsConfigError
from .origin import is_overbroad_wildcard_base, parse_origin_pattern
from .policy import (
    CONFIG_KEYS,
    FORBIDDEN_EXPOSE_HEADERS,
    MAX_MAX_AGE,
    MAX_REQUEST_HEADERS_LIMIT,
    MAX_REQUEST_HEADER_BYTES_LIMIT,
    header_is_browser_forbidden,
    header_is_hard_forbidden,
    validate_method,
)

LINT_WILDCARD_WITH_CREDENTIALS = "CORS_WILDCARD_WITH_CREDENTIALS"
LINT_NULL_ORIGIN_ALLOWED = "CORS_NULL_ORIGIN_ALLOWED"
LINT_PRIVATE_NETWORK_WITH_WILDCARD = "CORS_PRIVATE_NETWORK_WITH_WILDCARD"
LINT_INSECURE_HTTP_ORIGIN = "CORS_INSECURE_HTTP_ORIGIN"
LINT_OVERBROAD_SUBDOMAIN_WILDCARD = "CORS_OVERBROAD_SUBDOMAIN_WILDCARD"
LINT_UNSAFE_EXPOSE_HEADER = "CORS_UNSAFE_EXPOSE_HEADER"
LINT_INVALID_MAX_AGE = "CORS_INVALID_MAX_AGE"
LINT_INVALID_TYPE = "CORS_INVALID_TYPE"
LINT_UNKNOWN_OPTION = "CORS_UNKNOWN_OPTION"
LINT_INVALID_ORIGIN = "CORS_INVALID_ORIGIN"
LINT_INVALID_METHOD = "CORS_INVALID_METHOD"
LINT_INVALID_HEADER = "CORS_INVALID_HEADER"
LINT_UNSAFE_ALLOWED_HEADER = "CORS_UNSAFE_ALLOWED_HEADER"
LINT_REFLECT_ALL_ORIGINS = "CORS_REFLECT_ALL_ORIGINS"
LINT_DUPLICATE_ORIGIN = "CORS_DUPLICATE_ORIGIN"
LINT_NO_ORIGINS_CONFIGURED = "CORS_NO_ORIGINS_CONFIGURED"
LINT_REDUNDANT_ORIGIN_ENTRY = "CORS_REDUNDANT_ORIGIN_ENTRY"

LINT_CODES = frozenset(
    {
        LINT_WILDCARD_WITH_CREDENTIALS,
        LINT_NULL_ORIGIN_ALLOWED,
        LINT_PRIVATE_NETWORK_WITH_WILDCARD,
        LINT_INSECURE_HTTP_ORIGIN,
        LINT_OVERBROAD_SUBDOMAIN_WILDCARD,
        LINT_UNSAFE_EXPOSE_HEADER,
        LINT_INVALID_MAX_AGE,
        LINT_INVALID_TYPE,
        LINT_UNKNOWN_OPTION,
        LINT_INVALID_ORIGIN,
        LINT_INVALID_METHOD,
        LINT_INVALID_HEADER,
        LINT_UNSAFE_ALLOWED_HEADER,
        LINT_REFLECT_ALL_ORIGINS,
        LINT_DUPLICATE_ORIGIN,
        LINT_NO_ORIGINS_CONFIGURED,
        LINT_REDUNDANT_ORIGIN_ENTRY,
    }
)

_BOOLEAN_KEYS = (
    "allow_credentials",
    "allow_null_origin",
    "allow_http_localhost",
    "multi_level_subdomains",
    "allow_private_network",
    "allow_forbidden_headers",
)


@dataclass(frozen=True)
class CorsLintFinding:
    """One stable structured lint finding."""

    code: str
    severity: str
    message: str
    path: Optional[str]
    remediation: str

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "remediation": self.remediation,
        }


def _add(findings: List[CorsLintFinding], code: str, severity: str, message: str, remediation: str, path: Optional[str]) -> None:
    findings.append(CorsLintFinding(code, severity, message, path, remediation))


def _entries(value: object) -> Tuple[Optional[List[object]], bool]:
    if isinstance(value, str):
        return [value], True
    if isinstance(value, (list, tuple)):
        return list(value), True
    return None, False


def _lint_bounded_integer(
    findings: List[CorsLintFinding],
    config: Mapping[str, object],
    key: str,
    minimum: int,
    maximum: int,
    code: str = LINT_INVALID_TYPE,
) -> None:
    if key not in config:
        return
    value = config[key]
    if type(value) is not int or value < minimum or value > maximum:  # type: ignore[operator]
        _add(
            findings,
            code,
            "high",
            key + " must be an integer from " + str(minimum) + " through " + str(maximum) + ".",
            "Use a strict integer inside the enforced denial-of-service resistant range.",
            key,
        )


def lint_cors_config(config: object) -> Tuple[CorsLintFinding, ...]:
    """Audit a policy mapping and return immutable structured findings.

    The linter mirrors runtime validation without executing origin predicates.
    High and critical findings identify configurations rejected by the runtime
    or combinations that are especially dangerous. Medium and low findings are
    hardening and maintainability observations.
    """

    findings = []  # type: List[CorsLintFinding]
    if not isinstance(config, Mapping):
        _add(
            findings,
            LINT_INVALID_TYPE,
            "critical",
            "The policy configuration must be a mapping.",
            "Pass a dictionary or decoded JSON object to the policy validator.",
            None,
        )
        return tuple(findings)

    for key in config:
        if not isinstance(key, str):
            _add(
                findings,
                LINT_INVALID_TYPE,
                "critical",
                "Configuration keys must be strings.",
                "Use decoded JSON object keys or documented Python option names.",
                None,
            )
            continue
        if key not in CONFIG_KEYS:
            _add(
                findings,
                LINT_UNKNOWN_OPTION,
                "high",
                "Unknown option " + key + " will be rejected by the runtime validator.",
                "Remove the unknown option or check for a typo.",
                key,
            )

    for key in _BOOLEAN_KEYS:
        if key in config and type(config[key]) is not bool:
            _add(
                findings,
                LINT_INVALID_TYPE,
                "high",
                "Option " + key + " must be exactly true or false.",
                "Use a boolean. Truthy strings and integers are rejected by the runtime validator.",
                key,
            )

    if "max_age" in config:
        value = config["max_age"]
        if type(value) is not int or value < 0 or value > MAX_MAX_AGE:  # type: ignore[operator]
            _add(
                findings,
                LINT_INVALID_MAX_AGE,
                "high",
                "max_age must be an integer from 0 through 86400 seconds.",
                "Use a bounded integer. Long-lived preflight caches preserve mistakes.",
                "max_age",
            )
    _lint_bounded_integer(findings, config, "max_request_headers", 1, MAX_REQUEST_HEADERS_LIMIT)
    _lint_bounded_integer(findings, config, "max_request_headers_bytes", 128, MAX_REQUEST_HEADER_BYTES_LIMIT)

    credentials = config.get("allow_credentials") is True
    private_network = config.get("allow_private_network") is True
    allow_forbidden_headers = config.get("allow_forbidden_headers") is True

    raw_origins = config.get("allowed_origins", [])
    origin_entries, origins_valid_type = _entries(raw_origins)
    if not origins_valid_type:
        _add(
            findings,
            LINT_INVALID_TYPE,
            "high",
            "allowed_origins must be a string or a list of strings.",
            "Use exact serialized origins or scoped subdomain wildcard strings.",
            "allowed_origins",
        )
        origin_entries = []

    seen_origins = set()
    valid_entry_count = 0
    has_any_wildcard = False
    has_subdomain_wildcard = False
    for index, entry in enumerate(origin_entries or []):
        path = "allowed_origins[" + str(index) + "]"
        if not isinstance(entry, str):
            _add(
                findings,
                LINT_INVALID_TYPE,
                "high",
                "Origin entries must be strings.",
                "Use exact serialized origins or scoped subdomain wildcard strings.",
                path,
            )
            continue
        if entry == "*":
            if credentials:
                _add(
                    findings,
                    LINT_WILDCARD_WITH_CREDENTIALS,
                    "critical",
                    "The universal wildcard origin is combined with credentialed CORS.",
                    "Remove the wildcard or disable credentials. Credentialed responses must echo only exact authorized origins.",
                    path,
                )
            else:
                _add(
                    findings,
                    LINT_REFLECT_ALL_ORIGINS,
                    "high",
                    "The universal wildcard authorizes every syntactically valid secure origin for uncredentialed responses.",
                    "Use the wildcard only for intentionally public resources.",
                    path,
                )
            valid_entry_count += 1
            has_any_wildcard = True
            if "*" in seen_origins:
                _add(findings, LINT_DUPLICATE_ORIGIN, "low", "The origin entry is duplicated.", "Remove duplicate allowlist entries.", path)
            seen_origins.add("*")
            continue

        try:
            pattern = parse_origin_pattern(entry)
        except CorsConfigError as exc:
            _add(
                findings,
                LINT_INVALID_ORIGIN,
                "high",
                "The origin entry is malformed or prohibited: " + exc.reason,
                "Use a canonical serialized origin such as https://app.example.com.",
                path,
            )
            continue

        valid_entry_count += 1
        if pattern.type == "subdomain":
            has_subdomain_wildcard = True
            if is_overbroad_wildcard_base(pattern.host or ""):
                _add(
                    findings,
                    LINT_OVERBROAD_SUBDOMAIN_WILDCARD,
                    "high",
                    "The subdomain wildcard base is a public suffix or otherwise overbroad.",
                    "Scope the wildcard below a registrable domain that you control, such as https://*.example.com.",
                    path,
                )
            if pattern.scheme == "http":
                _add(
                    findings,
                    LINT_INSECURE_HTTP_ORIGIN,
                    "high",
                    "Plaintext http subdomain wildcards are prohibited.",
                    "Use https in production. Plain http is limited to exact localhost development origins.",
                    path,
                )
        if pattern.type == "exact" and pattern.scheme == "http":
            if not pattern.is_localhost:
                _add(
                    findings,
                    LINT_INSECURE_HTTP_ORIGIN,
                    "critical" if credentials else "high",
                    "An insecure non-localhost http origin is configured.",
                    "Use https in production. Plain http is limited to explicit localhost development origins.",
                    path,
                )
            else:
                _add(
                    findings,
                    LINT_INSECURE_HTTP_ORIGIN,
                    "medium",
                    "An insecure localhost http origin is configured for development use.",
                    "Keep this entry out of production configuration and use https where possible.",
                    path,
                )
        key = pattern.type + "|" + pattern.key
        if key in seen_origins:
            _add(findings, LINT_DUPLICATE_ORIGIN, "low", "The origin entry is duplicated.", "Remove duplicate allowlist entries.", path)
        seen_origins.add(key)

    predicate = config.get("allow_origin_predicate")
    if "allow_origin_predicate" in config:
        if not callable(predicate) or inspect.iscoroutinefunction(predicate):
            _add(
                findings,
                LINT_INVALID_TYPE,
                "high",
                "allow_origin_predicate must be a synchronous callable.",
                "Use a synchronous callable returning exactly true or false.",
                "allow_origin_predicate",
            )
        elif not origin_entries or credentials:
            _add(
                findings,
                LINT_REFLECT_ALL_ORIGINS,
                "high" if credentials else "medium",
                "A dynamic predicate can broaden the allowlist and requires manual review.",
                "Prefer exact static origins. If a predicate is necessary, require exact scheme, host and port checks.",
                "allow_origin_predicate",
            )

    if not origin_entries and predicate is None:
        _add(
            findings,
            LINT_NO_ORIGINS_CONFIGURED,
            "low",
            "No origins are configured, so the policy intentionally denies every CORS origin.",
            "Add explicit origins or keep this deny-all policy if that is intended.",
            "allowed_origins",
        )
    if has_any_wildcard and valid_entry_count > 1:
        _add(
            findings,
            LINT_REDUNDANT_ORIGIN_ENTRY,
            "low",
            "Exact or subdomain entries are redundant when the universal wildcard is present.",
            "Choose either the audited universal wildcard or a scoped allowlist.",
            "allowed_origins",
        )

    if config.get("allow_null_origin") is True:
        _add(
            findings,
            LINT_NULL_ORIGIN_ALLOWED,
            "critical" if credentials else "medium",
            "The opaque null origin is explicitly enabled.",
            "Keep allow_null_origin false unless a sandboxed browser context absolutely requires it. It is never valid with credentials.",
            "allow_null_origin",
        )
    if private_network and (has_any_wildcard or has_subdomain_wildcard):
        _add(
            findings,
            LINT_PRIVATE_NETWORK_WITH_WILDCARD,
            "high",
            "Private Network Access is enabled together with a wildcard origin.",
            "Use exact origins for Private Network Access. A wildcard makes local-network reachability depend on broad DNS control.",
            "allow_private_network",
        )

    expose_entries, expose_valid_type = _entries(config.get("expose_headers", []))
    if not expose_valid_type:
        _add(findings, LINT_INVALID_TYPE, "high", "expose_headers must be a string or a list of strings.", "Use exact RFC 9110 field names.", "expose_headers")
        expose_entries = []
    for index, entry in enumerate(expose_entries or []):
        path = "expose_headers[" + str(index) + "]"
        lower = validate_header_name(entry)
        if lower is None or lower == "*" or lower in FORBIDDEN_EXPOSE_HEADERS:
            _add(
                findings,
                LINT_UNSAFE_EXPOSE_HEADER,
                "critical" if isinstance(entry, str) and lower in FORBIDDEN_EXPOSE_HEADERS else "high",
                "An expose_headers entry is forbidden or not a legal explicit HTTP header name.",
                "Remove wildcard, malformed, Set-Cookie and Set-Cookie2 entries.",
                path,
            )

    allowed_entries, allowed_valid_type = _entries(config.get("allowed_headers", []))
    if not allowed_valid_type:
        _add(findings, LINT_INVALID_TYPE, "high", "allowed_headers must be a string or a list of strings.", "Use exact RFC 9110 field names.", "allowed_headers")
        allowed_entries = []
    for index, entry in enumerate(allowed_entries or []):
        path = "allowed_headers[" + str(index) + "]"
        lower = validate_header_name(entry)
        if lower is None or lower == "*":
            _add(
                findings,
                LINT_INVALID_HEADER,
                "high",
                "An allowed_headers entry is not a legal explicit HTTP header name.",
                "Use exact RFC 9110 field names. Wildcard request headers are prohibited.",
                path,
            )
        elif header_is_hard_forbidden(lower) or (header_is_browser_forbidden(lower) and not allow_forbidden_headers):
            _add(
                findings,
                LINT_UNSAFE_ALLOWED_HEADER,
                "critical" if header_is_hard_forbidden(lower) else "high",
                "A forbidden or browser-controlled request header appears in allowed_headers.",
                "Remove protocol, hop-by-hop, Cookie, sec-* and proxy-* headers from the allowlist.",
                path,
            )

    method_entries, methods_valid_type = _entries(config.get("allowed_methods", []))
    if not methods_valid_type:
        _add(findings, LINT_INVALID_TYPE, "high", "allowed_methods must be a string or a list of strings.", "Use explicit RFC 9110 method tokens.", "allowed_methods")
        method_entries = []
    if "allowed_methods" in config and methods_valid_type and not method_entries:
        _add(
            findings,
            LINT_INVALID_METHOD,
            "high",
            "The allowed_methods list is empty.",
            "Configure at least one safe method or omit the option to use secure defaults.",
            "allowed_methods",
        )
    for index, entry in enumerate(method_entries or []):
        if validate_method(entry) is None:
            _add(
                findings,
                LINT_INVALID_METHOD,
                "high",
                "An allowed_methods entry is not a safe RFC 9110 token or is a dangerous method.",
                "Remove TRACE, CONNECT, wildcard and malformed method tokens.",
                "allowed_methods[" + str(index) + "]",
            )

    return tuple(findings)


__all__ = [
    "CorsLintFinding",
    "LINT_CODES",
    "LINT_DUPLICATE_ORIGIN",
    "LINT_INSECURE_HTTP_ORIGIN",
    "LINT_INVALID_HEADER",
    "LINT_INVALID_MAX_AGE",
    "LINT_INVALID_METHOD",
    "LINT_INVALID_ORIGIN",
    "LINT_INVALID_TYPE",
    "LINT_NO_ORIGINS_CONFIGURED",
    "LINT_NULL_ORIGIN_ALLOWED",
    "LINT_OVERBROAD_SUBDOMAIN_WILDCARD",
    "LINT_PRIVATE_NETWORK_WITH_WILDCARD",
    "LINT_REDUNDANT_ORIGIN_ENTRY",
    "LINT_REFLECT_ALL_ORIGINS",
    "LINT_UNKNOWN_OPTION",
    "LINT_UNSAFE_ALLOWED_HEADER",
    "LINT_UNSAFE_EXPOSE_HEADER",
    "LINT_WILDCARD_WITH_CREDENTIALS",
    "lint_cors_config",
]
