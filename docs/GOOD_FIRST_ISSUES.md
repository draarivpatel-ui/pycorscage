# Good first issues

These ten starter specifications are deliberately narrow. Each should include
standard-library regression tests and documentation when behavior changes.

## 1. Additional public suffix fixtures

Add fixture-driven tests for more shared hosting suffixes and country-code
second-level suffixes. Do not import a full external suffix list. Document the
conservative detector boundary and add only well-sourced static entries.

## 2. CLI help snapshot coverage

Add tests that compare `pycorscage --help`, `check --help`, and `lint --help`
against stable expected sections. The goal is to catch accidental removal of
safety-related flags, not to freeze every whitespace character.

## 3. WSGI iterable lifecycle tests

Add focused tests proving that close-capable response iterables are returned
without premature closure and that application exceptions propagate unchanged
after header enforcement. Keep the tests framework-neutral.

## 4. ASGI non-HTTP scope matrix

Expand websocket, lifespan, and custom-scope pass-through tests. Prove that
messages are not copied or reordered for scopes outside HTTP enforcement.

## 5. Predicate audit examples

Write a short documentation section with safe and unsafe predicate examples.
The safe example must compare scheme, host suffix boundary, port, and trust
level explicitly. The unsafe example must remain documentation only.

## 6. Error code stability inventory

Add a machine-readable test inventory of public decision and lint codes. The
purpose is to make accidental renames visible during review. Do not turn every
internal reason string into a frozen API without discussion.

## 7. Vary fuzz corpus

Add deterministic seed-based generation of comma spacing, case variation,
duplicate tokens, invalid tokens, and `*` positions for `merge_vary`. Assert
case-insensitive deduplication and stable ordering.

## 8. CLI hostile filename fixtures

Add portable fixtures for Unicode and control-character-bearing config paths.
Assert that terminal output remains neutralized, that valid Unicode filenames
still work when the platform permits them, and that errors never echo raw
terminal control sequences.

## 9. Framework integration smoke examples

Create documentation-only examples for Flask, Django, FastAPI, and Starlette.
Do not add framework dependencies. Examples should use their documented WSGI
or ASGI wrapping points and warn against adding a second CORS middleware.

## 10. Packaging reproducibility probe

Extend `scripts/check_dist.py` to report uncompressed sizes and file counts in
a stable format. This makes release audit diffs easier without depending on
reproducible-build tooling.
