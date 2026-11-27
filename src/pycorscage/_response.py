"""Shared response-header enforcement for WSGI and ASGI adapters."""

from __future__ import annotations

from typing import Iterable, List, Tuple

from ._headers import validate_response_header
from .policy import CorsDecision
from .vary import merge_vary


def is_cors_response_header(name: str) -> bool:
    """Return whether a response field is controlled by this CORS policy."""

    lower = name.lower()
    return lower.startswith("access-control-allow-") or lower == "access-control-expose-headers"


def apply_decision_to_headers(response_headers: Iterable[Tuple[str, str]], decision: CorsDecision) -> List[Tuple[str, str]]:
    """Return a new header list with downstream CORS values stripped.

    The input iterable and its tuples are never mutated. Existing non-CORS
    headers and Vary tokens are preserved. Policy headers are authoritative on
    allowed responses, while disallowed responses emit no Access-Control
    grant headers at all.
    """

    kept = []  # type: List[Tuple[str, str]]
    vary_values = []
    for name, value in response_headers:
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("response headers must be string pairs")
        lower = name.lower()
        if is_cors_response_header(lower):
            continue
        if lower == "vary":
            vary_values.append(value)
            continue
        validate_response_header(name, value)
        kept.append((name, value))

    if decision.allowed:
        kept.extend(decision.headers.as_list())
    merged_vary = merge_vary(vary_values, decision.vary)
    if merged_vary:
        kept.append(("Vary", merged_vary))
    return kept


def terminal_preflight_headers(decision: CorsDecision) -> List[Tuple[str, str]]:
    """Build the complete terminal preflight response header list."""

    output = decision.headers.as_list() if decision.allowed else []
    merged_vary = merge_vary(None, decision.vary)
    if merged_vary:
        output.append(("Vary", merged_vary))
    return output


__all__ = ["apply_decision_to_headers", "is_cors_response_header", "terminal_preflight_headers"]
