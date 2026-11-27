"""Shared helpers for generated unittest matrices."""

from __future__ import annotations

import re


def add_matrix_tests(cls, prefix, cases, body):
    """Attach one independently counted unittest method per matrix case."""

    for index, case in enumerate(cases):
        name = "test_" + prefix + "_" + format(index + 1, "03d")

        def test(self, case=case, body=body):
            body(self, case)

        test.__name__ = name
        test.__doc__ = prefix + " " + repr(case)
        setattr(cls, name, test)
    return cls


def safe_fragment(value, limit=40):
    text = re.sub(r"[^0-9A-Za-z]+", "_", repr(value))
    return text[:limit].strip("_") or "case"
