"""Exception types used by pycorscage."""

from __future__ import annotations

from typing import Any, Optional


class CorsCageError(ValueError):
    """Base exception carrying a stable machine-readable code.

    The untrusted input is available as ``input`` for structured handling, but
    it is deliberately not interpolated into the exception text. This keeps
    control characters and terminal escape sequences out of ordinary logs.
    """

    def __init__(self, code: str, reason: str, input: Any = None) -> None:
        self.code = code
        self.reason = reason
        self.input = input
        super().__init__(code + ": " + reason)


class CorsConfigError(CorsCageError):
    """Raised when a policy configuration is invalid or unsafe."""

    def __init__(self, reason: str, input: Any = None, code: str = "ERR_CORS_CONFIG") -> None:
        super().__init__(code, reason, input)


class OriginParseError(CorsCageError):
    """Raised when an origin serialization is malformed."""

    def __init__(self, code: str, reason: str, input: Any = None) -> None:
        super().__init__(code, reason, input)


class CorsInputError(CorsCageError):
    """Raised for programmer input errors outside request evaluation."""

    def __init__(self, reason: str, input: Any = None) -> None:
        super().__init__("ERR_CORS_INPUT", reason, input)


ERROR_CODES = frozenset(
    {
        "ERR_CORS_CONFIG",
        "ERR_CORS_INPUT",
    }
)

__all__ = [
    "CorsCageError",
    "CorsConfigError",
    "CorsInputError",
    "ERROR_CODES",
    "OriginParseError",
]
