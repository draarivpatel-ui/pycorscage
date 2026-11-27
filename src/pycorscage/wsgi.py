"""Zero-dependency WSGI middleware for pycorscage."""

from __future__ import annotations

from http import HTTPStatus
from typing import Callable, Iterable, List, Tuple

from ._response import apply_decision_to_headers, terminal_preflight_headers
from .policy import CorsPolicy

_WSGI_HEADER_KEYS = (
    ("HTTP_ORIGIN", "Origin"),
    ("HTTP_ACCESS_CONTROL_REQUEST_METHOD", "Access-Control-Request-Method"),
    ("HTTP_ACCESS_CONTROL_REQUEST_HEADERS", "Access-Control-Request-Headers"),
    ("HTTP_ACCESS_CONTROL_REQUEST_PRIVATE_NETWORK", "Access-Control-Request-Private-Network"),
)


class WSGICorsMiddleware:
    """Drop-in WSGI middleware enforcing an immutable CorsPolicy.

    True CORS preflights are terminal and return 204 when authorized or 403
    when denied. Non-preflight requests continue to the wrapped application;
    the response interceptor strips downstream Access-Control grant headers,
    installs authoritative policy headers only when allowed, and merges Vary.
    """

    def __init__(self, app: Callable, policy: CorsPolicy) -> None:
        if not callable(app):
            raise TypeError("app must be a WSGI callable")
        if not isinstance(policy, CorsPolicy):
            raise TypeError("policy must be a CorsPolicy")
        self.app = app
        self.policy = policy

    @staticmethod
    def _request_headers(environ: dict) -> List[Tuple[str, str]]:
        headers = []
        for key, header_name in _WSGI_HEADER_KEYS:
            if key in environ:
                headers.append((header_name, environ[key]))
        return headers

    def __call__(self, environ: dict, start_response: Callable):
        method = environ.get("REQUEST_METHOD", "")
        decision = self.policy.evaluate(method, self._request_headers(environ))
        if decision.is_preflight:
            status_code = decision.status_code or 403
            try:
                phrase = HTTPStatus(status_code).phrase
            except ValueError:
                phrase = "Forbidden"
            start_response(str(status_code) + " " + phrase, terminal_preflight_headers(decision))
            return [b""]

        def cors_start_response(status: str, response_headers: Iterable[Tuple[str, str]], exc_info=None):
            enforced = apply_decision_to_headers(response_headers, decision)
            if exc_info is None:
                return start_response(status, enforced)
            return start_response(status, enforced, exc_info)

        return self.app(environ, cors_start_response)


__all__ = ["WSGICorsMiddleware"]
