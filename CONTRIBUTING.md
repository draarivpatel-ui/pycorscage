# Contributing

Contributions are welcome. The project is security-sensitive, so small and
reviewable changes are preferred over broad rewrites.

## Ground rules

- Preserve zero runtime dependencies.
- Preserve Python 3.9 through 3.13 compatibility.
- Use only the standard library in source and tests.
- Do not weaken fail-closed behavior to make a test or integration easier.
- Add regression tests for every security behavior change.
- Keep public API changes explicit and documented.
- Never commit credentials, tokens, private origin inventories, or local paths.

## Development setup

No package installation is required for tests:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

Build inspection:

```sh
python3 -m pip install build
python3 -m build
python3 scripts/check_dist.py
```

## Patch expectations

A strong patch includes:

1. a clear statement of the security or compatibility problem,
2. the smallest code change that addresses it,
3. deterministic tests covering the old failure and the new behavior,
4. documentation updates when behavior or configuration changes,
5. a note about backwards compatibility and migration cost.

## Review focus

Reviewers should pay particular attention to:

- canonicalization before comparison
- exact boolean and integer type validation
- case-insensitive duplicate handling
- cache dimensions and `Vary` preservation
- downstream header override resistance
- Python 3.9 parser compatibility
- accidental dependence on insertion order, locale, or platform behavior
