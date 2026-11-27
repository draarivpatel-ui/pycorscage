"""Cache-safe Vary header merging."""

from __future__ import annotations

from typing import Iterable, List

from .origin import TOKEN_RE


def _add_raw(raw: object, values: List[str], seen: set, state: dict) -> None:
    if raw is None:
        return
    if isinstance(raw, str):
        items = [raw]
    else:
        try:
            items = list(raw)  # type: ignore[arg-type]
        except TypeError:
            return
    for item in items:
        if not isinstance(item, str):
            continue
        for piece in item.split(","):
            token = piece.strip(" \t")
            if token == "*":
                state["star"] = True
                continue
            if not TOKEN_RE.match(token):
                continue
            key = token.lower()
            if key not in seen:
                seen.add(key)
                values.append(token)


def merge_vary(existing: object, added: object) -> str:
    """Merge Vary values with case-insensitive deduplication.

    Existing tokens keep their original order and casing. Added tokens are
    appended only when absent. If any input contains ``*``, the result is
    exactly ``*`` because that already means the response varies on everything.
    Invalid non-token fragments are ignored rather than emitted.
    """

    values = []  # type: List[str]
    seen = set()
    state = {"star": False}
    _add_raw(existing, values, seen, state)
    _add_raw(added, values, seen, state)
    if state["star"]:
        return "*"
    return ", ".join(values)


__all__ = ["merge_vary"]
