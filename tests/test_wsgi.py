"""WSGI middleware enforcement tests."""

from __future__ import annotations

import unittest

from pycorscage import WSGICorsMiddleware, create_cors_policy

from _support import add_matrix_tests


STALE_HEADERS = [
    "Access-Control-Allow-Origin",
    "access-control-allow-origin",
    "ACCESS-CONTROL-ALLOW-ORIGIN",
    "Access-Control-Allow-Credentials",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Private-Network",
    "Access-Control-Max-Age",
    "Access-Control-Expose-Headers",
    "access-control-expose-headers",
    "Access-Control-Allow-Unexpected",
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


def simple_app(environ, start_response, headers=None, body=b"ok", status="200 OK"):
    if headers is None:
        headers = [("Content-Type", "text/plain")]
    start_response(status, headers)
    return [body]


def run_wsgi(app, environ):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = list(headers)
        captured["exc_info"] = exc_info
        captured["argc"] = 2 if exc_info is None else 3
        return lambda data: None

    result = app(environ, start_response)
    captured["body"] = b"".join(result)
    if hasattr(result, "close"):
        result.close()
    return captured


def header_map(headers):
    return {name.lower(): value for name, value in headers}


class TestWSGIStaleHeaderStripping(unittest.TestCase):
    def check_stale_allowed(self, case):
        downstream = [("Content-Type", "text/plain"), (case, "https://evil.example")]
        policy = make_policy()
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: simple_app(environ, start_response, downstream), policy
        )
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://app.example.com"})
        lowered = {name.lower() for name, _value in result["headers"]}
        self.assertNotIn(case.lower(), lowered - {"access-control-allow-origin", "access-control-expose-headers"})
        if case.lower() == "access-control-allow-origin":
            self.assertEqual(header_map(result["headers"])["access-control-allow-origin"], "https://app.example.com")
        elif case.lower() == "access-control-expose-headers":
            self.assertEqual(header_map(result["headers"])["access-control-expose-headers"], "x-request-id")
        else:
            self.assertNotIn(case.lower(), header_map(result["headers"]))

    def check_stale_disallowed(self, case):
        downstream = [("Content-Type", "text/plain"), (case, "https://evil.example")]
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: simple_app(environ, start_response, downstream), make_policy()
        )
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://evil.example"})
        self.assertNotIn(case.lower(), {name.lower() for name, _value in result["headers"]})
        self.assertNotIn("access-control-allow-origin", header_map(result["headers"]))


add_matrix_tests(TestWSGIStaleHeaderStripping, "stale_allowed", STALE_HEADERS, TestWSGIStaleHeaderStripping.check_stale_allowed)
add_matrix_tests(TestWSGIStaleHeaderStripping, "stale_disallowed", STALE_HEADERS, TestWSGIStaleHeaderStripping.check_stale_disallowed)


class TestWSGIBehavior(unittest.TestCase):
    def test_allowed_actual_installs_policy_headers_and_vary(self):
        downstream = [("Content-Type", "text/plain"), ("Vary", "Accept-Encoding")]
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: simple_app(environ, start_response, downstream), make_policy()
        )
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://app.example.com"})
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"], b"ok")
        mapping = header_map(result["headers"])
        self.assertEqual(mapping["access-control-allow-origin"], "https://app.example.com")
        self.assertEqual(mapping["access-control-expose-headers"], "x-request-id")
        self.assertEqual(mapping["vary"], "Accept-Encoding, Origin")
        self.assertEqual(mapping["content-type"], "text/plain")

    def test_disallowed_actual_passes_through_without_grant(self):
        middleware = WSGICorsMiddleware(lambda environ, start_response: simple_app(environ, start_response), make_policy())
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://evil.example"})
        self.assertEqual(result["status"], "200 OK")
        self.assertEqual(result["body"], b"ok")
        mapping = header_map(result["headers"])
        self.assertNotIn("access-control-allow-origin", mapping)
        self.assertEqual(mapping["vary"], "Origin")

    def test_no_origin_passes_through_with_vary(self):
        middleware = WSGICorsMiddleware(lambda environ, start_response: simple_app(environ, start_response), make_policy())
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET"})
        self.assertEqual(result["body"], b"ok")
        self.assertEqual(header_map(result["headers"])["vary"], "Origin")
        self.assertNotIn("access-control-allow-origin", header_map(result["headers"]))

    def test_preflight_allowed_terminal_204(self):
        called = []

        def app(environ, start_response):
            called.append(True)
            return simple_app(environ, start_response)

        middleware = WSGICorsMiddleware(app, make_policy())
        result = run_wsgi(
            middleware,
            {
                "REQUEST_METHOD": "OPTIONS",
                "HTTP_ORIGIN": "https://app.example.com",
                "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
                "HTTP_ACCESS_CONTROL_REQUEST_HEADERS": "content-type",
            },
        )
        self.assertEqual(called, [])
        self.assertEqual(result["status"], "204 No Content")
        self.assertEqual(result["body"], b"")
        mapping = header_map(result["headers"])
        self.assertEqual(mapping["access-control-allow-origin"], "https://app.example.com")
        self.assertEqual(mapping["access-control-allow-methods"], "POST")
        self.assertEqual(mapping["access-control-allow-headers"], "content-type")
        self.assertEqual(mapping["access-control-max-age"], "30")

    def test_preflight_disallowed_terminal_403(self):
        called = []
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: called.append(True) or simple_app(environ, start_response), make_policy()
        )
        result = run_wsgi(
            middleware,
            {
                "REQUEST_METHOD": "OPTIONS",
                "HTTP_ORIGIN": "https://evil.example",
                "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
            },
        )
        self.assertEqual(called, [])
        self.assertEqual(result["status"], "403 Forbidden")
        self.assertEqual(result["body"], b"")
        mapping = header_map(result["headers"])
        self.assertNotIn("access-control-allow-origin", mapping)
        self.assertIn("origin", mapping["vary"].lower())

    def test_plain_options_passes_downstream(self):
        middleware = WSGICorsMiddleware(lambda environ, start_response: simple_app(environ, start_response), make_policy())
        result = run_wsgi(middleware, {"REQUEST_METHOD": "OPTIONS", "HTTP_ORIGIN": "https://app.example.com"})
        self.assertEqual(result["status"], "200 OK")
        self.assertNotIn("access-control-allow-methods", header_map(result["headers"]))

    def test_multiple_vary_headers_merge(self):
        downstream = [("Vary", "Accept-Encoding"), ("vary", "accept-language")]
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: simple_app(environ, start_response, downstream), make_policy()
        )
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://app.example.com"})
        vary_headers = [(name, value) for name, value in result["headers"] if name.lower() == "vary"]
        self.assertEqual(len(vary_headers), 1)
        self.assertEqual(vary_headers[0][1], "Accept-Encoding, accept-language, Origin")

    def test_vary_star_preserved_as_star(self):
        downstream = [("Vary", "*")]
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: simple_app(environ, start_response, downstream), make_policy()
        )
        result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://app.example.com"})
        self.assertEqual(header_map(result["headers"])["vary"], "*")

    def test_original_header_list_not_mutated(self):
        downstream = [("Access-Control-Allow-Origin", "https://evil.example"), ("Vary", "Accept-Encoding")]
        original = list(downstream)
        middleware = WSGICorsMiddleware(
            lambda environ, start_response: simple_app(environ, start_response, downstream), make_policy()
        )
        run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://app.example.com"})
        self.assertEqual(downstream, original)

    def test_environ_not_mutated(self):
        environ = {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": "https://app.example.com"}
        original = dict(environ)
        middleware = WSGICorsMiddleware(lambda env, start_response: simple_app(env, start_response), make_policy())
        run_wsgi(middleware, environ)
        self.assertEqual(environ, original)

    def test_exc_info_forwarded_when_supplied(self):
        marker = (TypeError, TypeError("x"), None)

        def app(environ, start_response):
            start_response("500 Error", [], marker)
            return [b"err"]

        def outer_start_response(status, headers, exc_info=None):
            outer_start_response.seen = (status, headers, exc_info)
            return lambda data: None

        outer_start_response.seen = None
        middleware = WSGICorsMiddleware(app, make_policy())
        list(middleware({"REQUEST_METHOD": "GET"}, outer_start_response))
        self.assertEqual(outer_start_response.seen[2], marker)

    def test_response_header_crlf_rejected_for_noncors_header(self):
        def app(environ, start_response):
            start_response("200 OK", [("X-Bad", "one\r\ntwo")])
            return [b"bad"]

        middleware = WSGICorsMiddleware(app, make_policy())
        with self.assertRaises(Exception):
            run_wsgi(middleware, {"REQUEST_METHOD": "GET"})

    def test_close_capable_iterable_is_preserved(self):
        class CloseIterable:
            def __init__(self):
                self.closed = False

            def __iter__(self):
                return iter([b"ok"])

            def close(self):
                self.closed = True

        iterable = CloseIterable()

        def app(environ, start_response):
            start_response("200 OK", [])
            return iterable

        result = WSGICorsMiddleware(app, make_policy())({"REQUEST_METHOD": "GET"}, lambda status, headers, exc_info=None: lambda data: None)
        self.assertIs(result, iterable)
        result.close()
        self.assertTrue(iterable.closed)

    def test_crlf_and_comma_environ_origins_fail_closed(self):
        middleware = WSGICorsMiddleware(lambda environ, start_response: simple_app(environ, start_response), make_policy())
        for origin in (
            "https://app.example.com\r\n",
            "https://app.example.com,https://evil.example",
        ):
            with self.subTest(origin=origin):
                result = run_wsgi(middleware, {"REQUEST_METHOD": "GET", "HTTP_ORIGIN": origin})
                self.assertNotIn("access-control-allow-origin", header_map(result["headers"]))

    def test_invalid_app_rejected(self):
        with self.assertRaises(TypeError):
            WSGICorsMiddleware(None, make_policy())

    def test_invalid_policy_rejected(self):
        with self.assertRaises(TypeError):
            WSGICorsMiddleware(lambda environ, start_response: [], object())

    def test_wsgiref_style_write_callable_returned(self):
        writes = []

        def start_response(status, headers, exc_info=None):
            return writes.append

        def app(environ, start_response):
            write = start_response("200 OK", [])
            write(b"first")
            return [b"second"]

        result = WSGICorsMiddleware(app, make_policy())({"REQUEST_METHOD": "GET"}, start_response)
        self.assertEqual(b"".join(result), b"second")
        self.assertEqual(writes, [b"first"])

    def test_preflight_vary_contains_all_dimensions(self):
        middleware = WSGICorsMiddleware(lambda environ, start_response: simple_app(environ, start_response), make_policy())
        result = run_wsgi(
            middleware,
            {
                "REQUEST_METHOD": "OPTIONS",
                "HTTP_ORIGIN": "https://app.example.com",
                "HTTP_ACCESS_CONTROL_REQUEST_METHOD": "POST",
            },
        )
        vary = header_map(result["headers"])["vary"]
        for token in ("Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers", "Access-Control-Request-Private-Network"):
            self.assertIn(token, vary)


if __name__ == "__main__":
    unittest.main()
