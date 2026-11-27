"""Zero-dependency ASGI 3.0 middleware for pycorscage."""

from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Iterable, List, Tuple

from ._response import apply_decision_to_headers, terminal_preflight_headers
from .policy import CorsPolicy

_Scope = Dict[str, Any]
_Message = Dict[str, Any]
_Receive = Callable[[], Awaitable[_Message]]
_Send = Callable[[_Message], Awaitable[None]]


def _encode_header_pairs(pairs: Iterable[Tuple[str, str]]) -> List[Tuple[bytes, bytes]]:
    return [(name.encode("latin-1"), value.encode("latin-1")) for name, value in pairs]


def _decode_header_pairs(pairs: Iterable[Tuple[bytes, bytes]]) -> List[Tuple[str, str]]:
    output = []
    for raw_name, raw_value in pairs:
        if not isinstance(raw_name, bytes) or not isinstance(raw_value, bytes):
            raise TypeError("ASGI response headers must be byte pairs")
        output.append((raw_name.decode("latin-1"), raw_value.decode("latin-1")))
    return output


class ASGICorsMiddleware:
    """Drop-in pure-stdlib ASGI 3.0 middleware enforcing a CorsPolicy.

    The adapter has no framework imports and works with any ASGI server or
    framework that follows the ASGI 3.0 callable contract. Only HTTP scopes
    are evaluated; websocket and lifespan scopes pass through unchanged.
    """

    def __init__(self, app: Callable, policy: CorsPolicy) -> None:
        if not callable(app):
            raise TypeError("app must be an ASGI callable")
        if not isinstance(policy, CorsPolicy):
            raise TypeError("policy must be a CorsPolicy")
        self.app = app
        self.policy = policy

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "")
        decision = self.policy.evaluate(method, scope.get("headers", []))
        if decision.is_preflight:
            await send(
                {
                    "type": "http.response.start",
                    "status": decision.status_code or 403,
                    "headers": _encode_header_pairs(terminal_preflight_headers(decision)),
                }
            )
            await send({"type": "http.response.body", "body": b""})
            return

        async def cors_send(message: _Message) -> None:
            if message.get("type") != "http.response.start":
                await send(message)
                return
            raw_headers = message.get("headers", [])
            decoded = _decode_header_pairs(raw_headers)
            enforced = apply_decision_to_headers(decoded, decision)
            updated = dict(message)
            updated["headers"] = _encode_header_pairs(enforced)
            await send(updated)

        await self.app(scope, receive, cors_send)


__all__ = ["ASGICorsMiddleware"]
