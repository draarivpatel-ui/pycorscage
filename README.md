# pycorscage

`pycorscage` is a zero-dependency Python 3.9+ CORS security policy engine with
strict origin parsing, WSGI middleware, ASGI middleware, and a command-line
configuration auditor. It treats CORS as a security boundary rather than a
string-concatenation feature.

The library never reflects arbitrary origins, never combines the universal
wildcard or opaque `null` origin with credentials, canonicalizes origins before
matching, validates preflight methods and header tokens, handles Private
Network Access explicitly, strips downstream CORS override attempts, and
preserves cache safety through disciplined `Vary` merging.

## Publication status

This repository is prepared for publication as `pycorscage==1.0.0`, but the
package is not claimed to be published on PyPI yet. Until the first PyPI
release is announced in this repository, install from a reviewed local
checkout:

```sh
python -m pip install /path/to/pycorscage
```

After publication the intended command will be:

```sh
python -m pip install pycorscage
```

## Threat model

CORS is a browser-enforced read and request permission system. It is not an
authentication system, not a firewall, not CSRF protection by itself, and not
a control over non-browser clients. A server must still authenticate and
authorize every request. This library addresses CORS-specific failures that
often weaken server-side authorization:

- arbitrary origin reflection and boolean-style origin footguns
- credentialed CORS combined with `*` or the opaque `null` origin
- malformed, whitespace-padded, control-character, userinfo, path-bearing,
  comma-joined or otherwise ambiguous origin values
- raw Unicode, bidirectional-control and confusable host smuggling
- explicit default-port confusion, leading-zero ports, port zero and out-of-range ports
- obfuscated IPv4 forms such as `127.1`, octal-looking octets, hexadecimal
  octets and integer-only hosts
- malformed IPv6 literals and IPv6 zone identifiers
- subdomain matching mistakes involving the apex, lookalike suffixes, wrong
  schemes, wrong ports, empty labels and public suffixes
- cache poisoning caused by missing, duplicated or clobbered `Vary` values
- preflight method and header injection or unbounded preflight header lists
- accidental Private Network Access exposure
- downstream applications silently overriding or reintroducing CORS grants
- exposing `Set-Cookie` or wildcard response headers to browser JavaScript

Outside scope: DNS rebinding, application authentication, CSRF tokens, reverse
proxy trust, non-browser clients, and schemes other than `http` and `https`.
Production policies are HTTPS-only. Plain HTTP is limited to exact localhost
development origins or the explicit `allow_http_localhost` development opt-in.

## Quick start

```python
from pycorscage import create_cors_policy

policy = create_cors_policy(
    allowed_origins=["https://app.example.com"],
    allow_credentials=True,
    allowed_methods=["GET", "POST"],
    allowed_headers=["content-type", "authorization"],
    expose_headers=["x-request-id"],
    max_age=600,
)

decision = policy.evaluate(
    "OPTIONS",
    {
        "Origin": "https://app.example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    },
)

assert decision.allowed is True
assert decision.is_preflight is True
assert decision.status_code == 204
assert decision.headers["access-control-allow-origin"] == "https://app.example.com"
```

`create_cors_policy` validates and copies caller input. The returned policy is
immutable. `CorsDecision` is frozen, its header mapping is immutable, and header
lookup is case-insensitive.

For non-preflight requests, `status_code` is `None` because the downstream
application generates the response. A denied non-preflight request is still
passed through by middleware, but every downstream CORS grant is stripped. This
matches what CORS can enforce: browsers block access to the response, while the
server remains responsible for its own request authorization. Preflights are
terminal and return 204 when authorized or 403 when denied.

## Strict origin parsing

```python
from pycorscage import normalize_origin, parse_origin

assert normalize_origin("HTTPS://EXAMPLE.COM:443") == "https://example.com"
assert normalize_origin("https://example.com:8443") == "https://example.com:8443"
assert normalize_origin("https://[2001:0db8:0:0:0:ff00:0042:8329]") == "https://[2001:db8::ff00:42:8329]"
```

`parse_origin` raises `OriginParseError` rather than repairing invalid input.
It rejects:

- leading or trailing whitespace
- spaces, control characters, NUL, CR, LF and raw non-ASCII characters
- comma-separated or whitespace-separated multiple origins
- userinfo such as `user:pass@host`
- paths, trailing slashes, queries, fragments, percent encoding and backslashes
- trailing root dots, empty labels, oversized labels and invalid hyphen positions
- obfuscated IPv4 forms such as `0177.0.0.1`, `127.1` and `2130706433`
- unbracketed or malformed IPv6 literals and zone identifiers
- empty ports, non-digit ports, leading-zero ports, port 0 and ports above 65535
- schemes other than `http` and `https`

The exact lowercase string `null` is recognized as the opaque origin
serialization. It is denied unless `allow_null_origin=True` is configured, and
that combination is a hard error whenever credentials are enabled.

## Exact origins and subdomain wildcards

Exact origins bind scheme, canonical host and effective port:

```python
policy = create_cors_policy(
    allowed_origins=[
        "https://app.example.com",
        "https://admin.example.com:8443",
    ]
)
```

A subdomain wildcard replaces one complete leftmost label by default:

```python
tenant_policy = create_cors_policy(
    allowed_origins=["https://*.example.com"]
)
```

With that configuration:

```text
https://tenant.example.com        allowed
https://example.com               denied
https://deep.tenant.example.com   denied
https://evil-example.com          denied
https://example.com.evil.example  denied
http://tenant.example.com         denied
https://tenant.example.com:8443   denied
```

Set `multi_level_subdomains=True` only when every nested subdomain is inside
the same trust boundary. Even then the apex never matches. Matching uses string
prefix and label operations, not regular expressions, so user-controlled host
text cannot create regex denial of service.

Wildcard bases that are public suffixes or otherwise overbroad are rejected at
configuration time. The conservative built-in detector covers single-label
suffixes such as `com`, common aggregated country-code suffixes such as
`co.uk`, and common shared hosting suffixes such as `github.io`. No bundled
suffix list can be complete, so exact origins remain the recommended default.
Plaintext HTTP subdomain wildcards are always rejected.

The standalone helper applies the same production scheme floor:

```python
from pycorscage import match_origin

assert match_origin("https://tenant.example.com", "https://*.example.com") is True
assert match_origin("https://example.com", "https://*.example.com") is False
```

## Credentials, null and the universal wildcard

The universal wildcard is only for intentionally public, uncredentialed
resources:

```python
public_policy = create_cors_policy(
    allowed_origins=["*"],
    allow_credentials=False,
)
```

Even with `*`, malformed origins and non-local plaintext HTTP do not pass.
These combinations are hard errors at policy creation time and are checked
again at runtime:

```python
create_cors_policy(allowed_origins=["*"], allow_credentials=True)
# raises CorsConfigError

create_cors_policy(allow_null_origin=True, allow_credentials=True)
# raises CorsConfigError

create_cors_policy(allowed_origins=["*"], allow_private_network=True)
# raises CorsConfigError
```

Credentialed responses echo the exact canonical origin. They never use `*`.
Uncredentialed wildcard responses use `*` only after strict syntax and scheme
validation.

## Origin predicates

An optional synchronous predicate can authorize origins outside the static
list. It runs only after strict parsing and the production scheme floor. It is
never called for malformed input or the opaque `null` origin.

```python
def tenant_allowed(origin):
    return (
        origin.scheme == "https"
        and origin.host is not None
        and origin.host.endswith(".example.com")
        and len(origin.host.split(".")) == 3
    )

policy = create_cors_policy(allow_origin_predicate=tenant_allowed)
```

The predicate receives an immutable `ParsedOrigin` with `normalized`, `scheme`,
`host`, `port`, `host_type` and `is_localhost` fields. It must return exactly
`True` or `False`. Exceptions and truthy non-booleans such as `"yes"` or `1`
fail closed. Static exact origins are preferable because a predicate can
recreate unsafe reflection if written incorrectly.

## Preflight validation

A true CORS preflight is exactly an `OPTIONS` request with both `Origin` and
`Access-Control-Request-Method`. A plain `OPTIONS` request is treated as an
actual request.

For preflights the engine enforces:

- one `Origin` value, never repeated or comma-joined
- one RFC 9110 token in `Access-Control-Request-Method`
- exact method allowlist membership, with `TRACE` and `CONNECT` always rejected
- strict comma-separated RFC 9110 header tokens in `Access-Control-Request-Headers`
- a default cap of 32 requested headers and 2048 bytes, configurable within
  hard ceilings
- exact `Access-Control-Request-Private-Network: true` parsing

`expose_headers` rejects wildcards, malformed tokens, `Set-Cookie` and
`Set-Cookie2`. `max_age` accepts only a strict integer from 0 through 86400;
booleans, floats, negative numbers and larger values are rejected.

## Private Network Access

Private Network Access is denied by default:

```python
policy = create_cors_policy(
    allowed_origins=["https://admin.example.com"],
    allow_private_network=True,
)
```

`Access-Control-Allow-Private-Network: true` is emitted only when all of these
hold:

1. the request is a valid preflight,
2. the origin is authorized,
3. the request header is exactly `Access-Control-Request-Private-Network: true`,
4. the policy explicitly opts in, and
5. the origin is not opaque or the universal wildcard.

The universal wildcard combined with `allow_private_network=True` is a hard
error. Subdomain wildcards with Private Network Access are accepted only
because they can be technically scoped, but the linter marks them high risk.
Exact origins are strongly recommended.

## Vary discipline and cache safety

`merge_vary` performs case-insensitive deduplication while preserving existing
token order and casing:

```python
from pycorscage import merge_vary

assert merge_vary("Accept-Encoding, origin", ["Origin", "Access-Control-Request-Method"]) == (
    "Accept-Encoding, origin, Access-Control-Request-Method"
)
assert merge_vary("*", "Origin") == "*"
```

Policy evaluation always includes `Origin` in `vary`. Preflight decisions also
include the three preflight request dimensions. Middleware merges those values
into both allowed and disallowed responses, so a shared cache cannot reuse a
response across origins or preflight shapes without the correct cache keys.

## WSGI middleware

```python
from pycorscage import WSGICorsMiddleware, create_cors_policy

policy = create_cors_policy(
    allowed_origins=["https://app.example.com"],
    allow_credentials=True,
    allowed_headers=["content-type", "authorization"],
)

def app(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"hello"]

application = WSGICorsMiddleware(app, policy)
```

The middleware is ordinary WSGI and works with frameworks and servers that
follow the WSGI contract, including Flask, Django, Gunicorn and `wsgiref`. It
does not import those frameworks.

Behavior:

- true preflights are terminal with 204 or 403
- non-preflight requests continue to the application
- downstream `Access-Control-Allow-*`, `Access-Control-Max-Age` and
  `Access-Control-Expose-Headers` values are stripped before policy headers are installed
- disallowed downstream responses receive no CORS grant
- existing `Vary` values are preserved and merged without mutating caller data

## ASGI middleware

```python
from pycorscage import ASGICorsMiddleware, create_cors_policy

policy = create_cors_policy(allowed_origins=["https://app.example.com"])

async def app(scope, receive, send):
    await send({
        "type": "http.response.start",
        "status": 200,
        "headers": [(b"content-type", b"text/plain")],
    })
    await send({"type": "http.response.body", "body": b"hello"})

application = ASGICorsMiddleware(app, policy)
```

The middleware implements the ASGI 3.0 callable contract using only the
standard library. It is suitable for FastAPI, Starlette, Quart, Litestar and
Uvicorn deployments without importing any of them. HTTP scopes are enforced;
websocket and lifespan scopes pass through unchanged.

## CLI auditor

Evaluate one actual request:

```sh
pycorscage check \
  --config policy.json \
  --origin https://app.example.com \
  --method GET
```

Evaluate one preflight:

```sh
pycorscage check \
  --config policy.json \
  --origin https://app.example.com \
  --method POST \
  --request-headers content-type,authorization \
  --preflight \
  --json
```

Audit a configuration:

```sh
pycorscage lint --config policy.json
pycorscage lint --config policy.json --json
```

Exit codes:

- `0`: check is allowed, or lint has no findings
- `1`: check is denied, or lint has findings
- `2`: command-line, file safety, JSON or policy-loading error

The CLI opens configuration with `os.open` using `O_NOFOLLOW` and `O_NONBLOCK`
where available, then verifies with `os.fstat` that the target is a regular
file. Directories, devices, FIFOs, symlinks, files over 1048576 bytes, JSON
nested beyond 128 container levels, duplicate object keys and non-standard JSON
constants are rejected. Errors and output are neutralized so filenames or input
cannot inject terminal control sequences.

## Configuration keys

| Key | Default | Meaning |
| --- | --- | --- |
| `allowed_origins` | `[]` | Exact origins, scoped subdomain wildcards or `*` |
| `allow_credentials` | `false` | Emit `Access-Control-Allow-Credentials: true` |
| `allowed_methods` | `GET, HEAD, POST` | Exact preflight method allowlist |
| `allowed_headers` | `[]` | Lower-case-insensitive preflight header allowlist |
| `expose_headers` | `[]` | Response headers exposed to browser JavaScript |
| `max_age` | `600` | Preflight cache lifetime, 0 through 86400 |
| `allow_null_origin` | `false` | Explicit opaque-origin opt-in, never with credentials |
| `allow_http_localhost` | `false` | Development-only plaintext loopback scheme relaxation |
| `multi_level_subdomains` | `false` | Permit nested subdomain wildcard matches |
| `allow_private_network` | `false` | Private Network Access opt-in |
| `allow_origin_predicate` | `None` | Synchronous dynamic allowlist predicate |
| `max_request_headers` | `32` | Maximum requested header count, 1 through 128 |
| `max_request_headers_bytes` | `2048` | Maximum raw requested header bytes, 128 through 16384 |
| `allow_forbidden_headers` | `false` | Allow browser-forbidden but non-protocol headers after review |

## Lint finding codes

| Code | Meaning |
| --- | --- |
| `CORS_WILDCARD_WITH_CREDENTIALS` | Universal wildcard combined with credentials |
| `CORS_NULL_ORIGIN_ALLOWED` | Opaque null origin explicitly enabled |
| `CORS_PRIVATE_NETWORK_WITH_WILDCARD` | Private Network Access combined with wildcard scope |
| `CORS_INSECURE_HTTP_ORIGIN` | Plaintext HTTP origin or prohibited HTTP wildcard |
| `CORS_OVERBROAD_SUBDOMAIN_WILDCARD` | Wildcard base is a public suffix or too broad |
| `CORS_UNSAFE_EXPOSE_HEADER` | Wildcard, malformed or forbidden exposed response header |
| `CORS_INVALID_MAX_AGE` | max_age is not a bounded strict integer |
| `CORS_INVALID_TYPE` | A configuration value has an invalid type |
| `CORS_UNKNOWN_OPTION` | Unknown key that runtime validation rejects |
| `CORS_INVALID_ORIGIN` | Malformed or prohibited origin entry |
| `CORS_INVALID_METHOD` | Malformed, empty or dangerous method entry |
| `CORS_INVALID_HEADER` | Malformed or wildcard request header entry |
| `CORS_UNSAFE_ALLOWED_HEADER` | Browser-controlled or protocol request header allowed |
| `CORS_REFLECT_ALL_ORIGINS` | Universal or predicate-based broad reflection risk |
| `CORS_DUPLICATE_ORIGIN` | Duplicate canonical allowlist entry |
| `CORS_NO_ORIGINS_CONFIGURED` | Policy intentionally denies all origins |
| `CORS_REDUNDANT_ORIGIN_ENTRY` | Scoped entries are redundant beside universal wildcard |

The linter mirrors runtime rejection rules without executing predicates. High
and critical findings identify unsafe or runtime-rejected configuration;
medium and low findings are hardening and maintainability observations.

## Development

The regression suite currently runs 887 independently counted tests. Run the
standard-library test suite:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run a build inspection:

```sh
python3 -m pip install build
python3 -m build
python3 scripts/check_dist.py
```

The project has zero runtime dependencies. Contributions must preserve Python
3.9 compatibility, strict fail-closed behavior, cache safety and deterministic
tests.
