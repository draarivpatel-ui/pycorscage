"""pycorscage: strict zero-dependency CORS policy enforcement.

The package provides a framework-independent policy engine, WSGI and ASGI
middleware, strict origin parsing, cache-safe Vary merging, a structured
configuration linter, and the ``pycorscage`` command-line auditor.
"""

from __future__ import annotations

from .asgi import ASGICorsMiddleware
from .errors import CorsCageError, CorsConfigError, CorsInputError, OriginParseError
from .linter import CorsLintFinding, lint_cors_config
from .origin import ParsedOrigin, match_origin, normalize_origin, parse_origin, try_parse_origin
from .policy import CorsDecision, CorsPolicy, create_cors_policy
from .vary import merge_vary
from .wsgi import WSGICorsMiddleware

__version__ = "1.0.0"

__all__ = [
    "ASGICorsMiddleware",
    "CorsCageError",
    "CorsConfigError",
    "CorsDecision",
    "CorsInputError",
    "CorsLintFinding",
    "CorsPolicy",
    "OriginParseError",
    "ParsedOrigin",
    "WSGICorsMiddleware",
    "__version__",
    "create_cors_policy",
    "lint_cors_config",
    "match_origin",
    "merge_vary",
    "normalize_origin",
    "parse_origin",
    "try_parse_origin",
]
