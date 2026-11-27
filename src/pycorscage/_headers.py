"""Internal and public immutable HTTP header helpers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Tuple

from .errors import CorsInputError
from .origin import MAX_HEADER_NAME_LENGTH, TOKEN_RE

_HEADER_VALUE_RE_CHARS = set(chr(value) for value in range(0x20, 0x7F))
_HEADER_VALUE_RE_CHARS.add("\t")


class ImmutableHeaders(Mapping):
    """Small immutable case-insensitive header mapping.

    Iteration preserves the canonical casing supplied at construction. Lookup
    is case-insensitive, as HTTP field-name lookup should be.
    """

    __slots__ = ("_items", "_lookup")

    def __init__(self, items=()) -> None:
        if isinstance(items, Mapping):
            iterable = items.items()
        else:
            iterable = items
        output = []  # type: List[Tuple[str, str]]
        lookup = {}
        for pair in iterable:
            try:
                name, value = pair
            except (TypeError, ValueError) as exc:
                raise CorsInputError("headers must contain name and value pairs", pair) from exc
            if not isinstance(name, str) or not isinstance(value, str):
                raise CorsInputError("header names and values must be strings", pair)
            validate_response_header(name, value)
            key = name.lower()
            if key in lookup:
                raise CorsInputError("duplicate response header name", name)
            output.append((name, value))
            lookup[key] = value
        object.__setattr__(self, "_items", tuple(output))
        object.__setattr__(self, "_lookup", lookup)

    def __getitem__(self, name: str) -> str:
        if not isinstance(name, str):
            raise KeyError(name)
        return self._lookup[name.lower()]

    def __iter__(self) -> Iterator[str]:
        for name, _value in self._items:
            yield name

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and name.lower() in self._lookup

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return False
        try:
            other_lookup = {str(key).lower(): value for key, value in other.items()}
        except (AttributeError, TypeError, ValueError):
            return False
        return self._lookup == other_lookup

    def __repr__(self) -> str:
        return "ImmutableHeaders(" + repr(self._items) + ")"

    def as_list(self) -> List[Tuple[str, str]]:
        """Return a copy of the canonical wire-format pairs."""

        return list(self._items)

    def lower_items(self) -> Iterator[Tuple[str, str]]:
        """Iterate lower-case names with values."""

        for name, value in self._items:
            yield name.lower(), value


@dataclass(frozen=True)
class HeaderState:
    present: bool
    valid: bool
    multiple: bool
    value: Optional[str]


@dataclass(frozen=True)
class RequestHeaders:
    values: Tuple[Tuple[str, Tuple[object, ...]], ...]
    malformed: bool = False

    def state(self, name: str) -> HeaderState:
        lower = name.lower()
        found = []  # type: List[object]
        for key, values in self.values:
            if key == lower:
                found.extend(values)
        if not found:
            return HeaderState(False, False, False, None)
        multiple = len(found) != 1
        valid = True
        value = None  # type: Optional[object]
        if len(found) == 1:
            value = found[0]
            if isinstance(value, (list, tuple)):
                if len(value) != 1:
                    multiple = True
                    valid = False
                    value = None
                else:
                    value = value[0]
            if isinstance(value, bytes):
                try:
                    value = value.decode("latin-1")
                except UnicodeDecodeError:
                    valid = False
                    value = None
            if value is not None and not isinstance(value, str):
                valid = False
                value = None
        if multiple:
            valid = False
            value = None
        return HeaderState(True, valid, multiple, value if isinstance(value, str) else None)


def collect_request_headers(headers: object) -> RequestHeaders:
    """Collect request headers without losing repeated field names."""

    if headers is None:
        return RequestHeaders(())
    if isinstance(headers, Mapping):
        iterable = headers.items()
    else:
        try:
            iterable = iter(headers)  # type: ignore[arg-type]
        except TypeError:
            return RequestHeaders((), True)

    grouped = {}
    order = []  # type: List[str]
    malformed = False
    for pair in iterable:
        try:
            raw_name, raw_value = pair
        except (TypeError, ValueError):
            malformed = True
            continue
        if isinstance(raw_name, bytes):
            try:
                name = raw_name.decode("latin-1")
            except UnicodeDecodeError:
                malformed = True
                continue
        elif isinstance(raw_name, str):
            name = raw_name
        else:
            malformed = True
            continue
        lower = name.lower()
        if lower not in grouped:
            grouped[lower] = []
            order.append(lower)
        grouped[lower].append(raw_value)
    return RequestHeaders(tuple((key, tuple(grouped[key])) for key in order), malformed)


def validate_response_header(name: str, value: str) -> None:
    """Validate one outgoing response header pair against response splitting."""

    if not isinstance(name, str) or not isinstance(value, str):
        raise CorsInputError("header names and values must be strings")
    if len(name) == 0 or len(name) > MAX_HEADER_NAME_LENGTH or not TOKEN_RE.match(name):
        raise CorsInputError("response header name is not an RFC 9110 token", name)
    if any(char not in _HEADER_VALUE_RE_CHARS for char in value):
        raise CorsInputError("response header value contains control or non-ASCII characters", name)


def validate_header_name(value: object) -> Optional[str]:
    """Return a lower-case RFC 9110 field name or None."""

    if not isinstance(value, str):
        return None
    if len(value) == 0 or len(value) > MAX_HEADER_NAME_LENGTH:
        return None
    lower = value.lower()
    if not TOKEN_RE.match(lower):
        return None
    return lower


__all__ = [
    "HeaderState",
    "ImmutableHeaders",
    "RequestHeaders",
    "collect_request_headers",
    "validate_header_name",
    "validate_response_header",
]
