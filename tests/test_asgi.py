"""ASGI 3.0 middleware enforcement tests using asyncio.run."""

from __future__ import annotations

import asyncio
import unittest

from pycorscage import ASGICorsMiddleware, create_cors_policy

from _support import add_matrix_tests


STALE_HEADERS = [
    b"access-control-allow-origin",
    b"Access-Control-Allow-Origin",
    b"access-control-allow-credentials",
    b"access-control-allow-methods",
    b"access-control-allow-headers",
    b"access-control-allow-private-network",
    b"Access-Control-Max-Age",
    b"access-control-expose-headers",
    b"Access-Control-Expose-Headers",
    b"access-control-allow-unexpected",
]


def make_policy(**overrides):
    config = {
        "allowed_origins": ["https://app.example.com"],
        "allowed_methods": ["GET", "POST"],
        "allowed_headers": ["content-type"],
        "expose_headers": ["x-request-id"],
        "max_age": 30,
    }
    config.update(overrides)
    return create_cors_policy(**config)


async def simple_asgi(scope, receive, send, headers=None, body=b"ok", status=200):
    if headers is None:
        headers = [(b"content-type", b"text/plain")]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def run_asgi(app, scope):
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    return messages


def start_message(messages):
    return next(message for message in messages if message["type"] == "http.response.start")


def header_map_bytes(headers):
    return {name.lower(): value for name, value in headers}


class TestASGIStaleHeaderStripping(unittest.TestCase):
    def check_stale_allowed(self, case):
        async def app(scope, receive, send):
            await simple_asgi(scope, receive, send, [(b"content-type", b"text/plain"), (case, b"https://evil.example")])

        middleware = ASGICorsMiddleware(app, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://app.example.com")], "path": "/"},
        )
        mapping = header_map_bytes(start_message(messages)["headers"])
        if case.lower() == b"access-control-allow-origin":
            self.assertEqual(mapping[b"access-control-allow-origin"], b"https://app.example.com")
        elif case.lower() == b"access-control-expose-headers":
            self.assertEqual(mapping[b"access-control-expose-headers"], b"x-request-id")
        else:
            self.assertNotIn(case.lower(), mapping)

    def check_stale_disallowed(self, case):
        async def app(scope, receive, send):
            await simple_asgi(scope, receive, send, [(b"content-type", b"text/plain"), (case, b"https://evil.example")])

        middleware = ASGICorsMiddleware(app, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://evil.example")], "path": "/"},
        )
        mapping = header_map_bytes(start_message(messages)["headers"])
        self.assertNotIn(case.lower(), mapping)
        self.assertNotIn(b"access-control-allow-origin", mapping)


add_matrix_tests(TestASGIStaleHeaderStripping, "stale_allowed", STALE_HEADERS, TestASGIStaleHeaderStripping.check_stale_allowed)
add_matrix_tests(TestASGIStaleHeaderStripping, "stale_disallowed", STALE_HEADERS, TestASGIStaleHeaderStripping.check_stale_disallowed)


class TestASGIBehavior(unittest.TestCase):
    def test_allowed_actual_installs_policy_headers(self):
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://app.example.com")], "path": "/"},
        )
        start = start_message(messages)
        self.assertEqual(start["status"], 200)
        mapping = header_map_bytes(start["headers"])
        self.assertEqual(mapping[b"access-control-allow-origin"], b"https://app.example.com")
        self.assertEqual(mapping[b"access-control-expose-headers"], b"x-request-id")
        self.assertEqual(mapping[b"vary"], b"Origin")
        self.assertEqual(messages[-1]["body"], b"ok")

    def test_disallowed_actual_passes_through_without_grant(self):
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://evil.example")], "path": "/"},
        )
        start = start_message(messages)
        self.assertEqual(start["status"], 200)
        mapping = header_map_bytes(start["headers"])
        self.assertNotIn(b"access-control-allow-origin", mapping)
        self.assertEqual(mapping[b"vary"], b"Origin")
        self.assertEqual(messages[-1]["body"], b"ok")

    def test_preflight_allowed_terminal_204(self):
        called = []

        async def app(scope, receive, send):
            called.append(True)
            await simple_asgi(scope, receive, send)

        middleware = ASGICorsMiddleware(app, make_policy())
        messages = run_asgi(
            middleware,
            {
                "type": "http",
                "method": "OPTIONS",
                "headers": [
                    (b"origin", b"https://app.example.com"),
                    (b"access-control-request-method", b"POST"),
                    (b"access-control-request-headers", b"content-type"),
                ],
                "path": "/",
            },
        )
        self.assertEqual(called, [])
        self.assertEqual(messages[0]["status"], 204)
        self.assertEqual(messages[1]["body"], b"")
        mapping = header_map_bytes(messages[0]["headers"])
        self.assertEqual(mapping[b"access-control-allow-methods"], b"POST")
        self.assertEqual(mapping[b"access-control-allow-headers"], b"content-type")

    def test_preflight_disallowed_terminal_403(self):
        called = []

        async def app(scope, receive, send):
            called.append(True)
            await simple_asgi(scope, receive, send)

        middleware = ASGICorsMiddleware(app, make_policy())
        messages = run_asgi(
            middleware,
            {
                "type": "http",
                "method": "OPTIONS",
                "headers": [(b"origin", b"https://evil.example"), (b"access-control-request-method", b"POST")],
                "path": "/",
            },
        )
        self.assertEqual(called, [])
        self.assertEqual(messages[0]["status"], 403)
        self.assertEqual(messages[1]["body"], b"")
        mapping = header_map_bytes(messages[0]["headers"])
        self.assertNotIn(b"access-control-allow-origin", mapping)
        self.assertIn(b"origin", mapping[b"vary"].lower())

    def test_plain_options_passes_downstream(self):
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "OPTIONS", "headers": [(b"origin", b"https://app.example.com")], "path": "/"},
        )
        self.assertEqual(start_message(messages)["status"], 200)
        self.assertNotIn(b"access-control-allow-methods", header_map_bytes(start_message(messages)["headers"]))

    def test_multiple_vary_headers_merge_to_one(self):
        async def app(scope, receive, send):
            await simple_asgi(
                scope,
                receive,
                send,
                [(b"vary", b"Accept-Encoding"), (b"Vary", b"accept-language")],
            )

        middleware = ASGICorsMiddleware(app, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://app.example.com")], "path": "/"},
        )
        vary_headers = [(name, value) for name, value in start_message(messages)["headers"] if name.lower() == b"vary"]
        self.assertEqual(len(vary_headers), 1)
        self.assertEqual(vary_headers[0][1], b"Accept-Encoding, accept-language, Origin")

    def test_vary_star_preserved(self):
        async def app(scope, receive, send):
            await simple_asgi(scope, receive, send, [(b"vary", b"*")])

        middleware = ASGICorsMiddleware(app, make_policy())
        messages = run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://app.example.com")], "path": "/"},
        )
        self.assertEqual(header_map_bytes(start_message(messages)["headers"])[b"vary"], b"*")

    def test_response_message_and_header_list_not_mutated(self):
        downstream_headers = [(b"access-control-allow-origin", b"https://evil.example"), (b"vary", b"accept-encoding")]
        original_headers = list(downstream_headers)
        seen_message_ids = []

        async def app(scope, receive, send):
            message = {"type": "http.response.start", "status": 200, "headers": downstream_headers}
            seen_message_ids.append(message)
            await send(message)
            await send({"type": "http.response.body", "body": b"ok"})

        middleware = ASGICorsMiddleware(app, make_policy())
        run_asgi(
            middleware,
            {"type": "http", "method": "GET", "headers": [(b"origin", b"https://app.example.com")], "path": "/"},
        )
        self.assertEqual(downstream_headers, original_headers)
        self.assertEqual(seen_message_ids[0]["headers"], original_headers)

    def test_non_http_websocket_scope_passes_through(self):
        events = []

        async def app(scope, receive, send):
            events.append(scope["type"])
            await send({"type": "websocket.accept"})

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            events.append(message)

        async def runner():
            await ASGICorsMiddleware(app, make_policy())({"type": "websocket", "headers": []}, receive, send)

        asyncio.run(runner())
        self.assertEqual(events[0], "websocket")
        self.assertEqual(events[1], {"type": "websocket.accept"})

    def test_lifespan_scope_passes_through(self):
        events = []

        async def app(scope, receive, send):
            events.append(scope["type"])

        async def receive():
            return {"type": "lifespan.startup"}

        async def send(message):
            events.append(message)

        async def runner():
            await ASGICorsMiddleware(app, make_policy())({"type": "lifespan"}, receive, send)

        asyncio.run(runner())
        self.assertEqual(events, ["lifespan"])

    def test_duplicate_origin_bytes_fail_closed(self):
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        messages = run_asgi(
            middleware,
            {
                "type": "http",
                "method": "GET",
                "headers": [(b"origin", b"https://app.example.com"), (b"origin", b"https://app.example.com")],
                "path": "/",
            },
        )
        mapping = header_map_bytes(start_message(messages)["headers"])
        self.assertNotIn(b"access-control-allow-origin", mapping)

    def test_duplicate_origin_bytes_good_and_evil_fail_closed(self):
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        for first, second in (
            (b"https://app.example.com", b"https://evil.example"),
            (b"https://evil.example", b"https://app.example.com"),
        ):
            with self.subTest(first=first, second=second):
                messages = run_asgi(
                    middleware,
                    {
                        "type": "http",
                        "method": "GET",
                        "headers": [(b"origin", first), (b"origin", second)],
                        "path": "/",
                    },
                )
                mapping = header_map_bytes(start_message(messages)["headers"])
                self.assertNotIn(b"access-control-allow-origin", mapping)

    def test_control_and_latin1_origin_bytes_fail_closed(self):
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        for raw_origin in (
            b"https://app.example.com\xff",
            b"https://app.example.com\r\n",
            b"\xff",
        ):
            with self.subTest(raw_origin=raw_origin):
                messages = run_asgi(
                    middleware,
                    {"type": "http", "method": "GET", "headers": [(b"origin", raw_origin)], "path": "/"},
                )
                mapping = header_map_bytes(start_message(messages)["headers"])
                self.assertNotIn(b"access-control-allow-origin", mapping)

    def test_non_byte_response_headers_rejected(self):
        async def app(scope, receive, send):
            await simple_asgi(scope, receive, send, [("content-type", "text/plain")])

        middleware = ASGICorsMiddleware(app, make_policy())
        with self.assertRaises(TypeError):
            run_asgi(middleware, {"type": "http", "method": "GET", "headers": []})

    def test_invalid_app_rejected(self):
        with self.assertRaises(TypeError):
            ASGICorsMiddleware(None, make_policy())

    def test_invalid_policy_rejected(self):
        with self.assertRaises(TypeError):
            ASGICorsMiddleware(simple_asgi, object())

    def test_scope_not_mutated(self):
        scope = {"type": "http", "method": "GET", "headers": [(b"origin", b"https://app.example.com")], "path": "/"}
        original = dict(scope)
        middleware = ASGICorsMiddleware(simple_asgi, make_policy())
        run_asgi(middleware, scope)
        self.assertEqual(scope, original)


if __name__ == "__main__":
    unittest.main()
