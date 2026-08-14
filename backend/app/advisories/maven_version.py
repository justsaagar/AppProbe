"""Maven version comparison (ComparableVersion semantics).

Used for OSV ECOSYSTEM ranges on Maven coordinates. This is not a naive
string comparison: ``1.9.0`` is less than ``1.10.0``.
"""

from __future__ import annotations

import re
from functools import total_ordering
from typing import Any

_QUALIFIER_RANK = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "rc": 3,
    "cr": 3,
    "snapshot": 4,
    "": 5,
    "ga": 5,
    "final": 5,
    "release": 5,
    "sp": 6,
}

_TOKEN = re.compile(r"(\d+)|([a-zA-Z]+)|([.-]+)")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9._+\-]+$")


def is_usable_version(value: str | None) -> bool:
    if not value:
        return False
    stripped = value.strip()
    if not stripped or len(stripped) > 64:
        return False
    if stripped.lower() in {
        "latest",
        "unknown",
        "null",
        "undefined",
        "none",
        "snapshot",
        "release",
        "dev",
        "master",
        "main",
        "head",
    }:
        return False
    return bool(_SAFE_VERSION.match(stripped))


@total_ordering
class MavenVersion:
    def __init__(self, value: str) -> None:
        if not is_usable_version(value):
            raise ValueError(f"unusable Maven version: {value!r}")
        self.original = value.strip()
        self._items = _parse(self.original.lower())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, MavenVersion):
            return NotImplemented
        return _compare(self._items, other._items) == 0

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, MavenVersion):
            return NotImplemented
        return _compare(self._items, other._items) < 0

    def __hash__(self) -> int:
        return hash(tuple(self._items))

    def __repr__(self) -> str:
        return f"MavenVersion({self.original!r})"


def maven_cmp(left: str, right: str) -> int:
    return _compare(MavenVersion(left)._items, MavenVersion(right)._items)


def _parse(version: str) -> list[Any]:
    tokens: list[str] = []
    for match in _TOKEN.finditer(version):
        number, word, _sep = match.groups()
        if number is not None:
            tokens.append(number)
        elif word is not None:
            tokens.append(word)
    items: list[Any] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token.isdigit():
            items.append(int(token))
            i += 1
            continue
        # Hyphen-prefixed qualifier starts a sub-list analog: keep as qualifier item.
        items.append(_qualifier(token))
        i += 1
    return _trim(items)


def _qualifier(token: str) -> tuple[int, str | int]:
    rank = _QUALIFIER_RANK.get(token)
    if rank is not None:
        return (1, rank)
    return (1, token)


def _trim(items: list[Any]) -> list[Any]:
    while items:
        last = items[-1]
        if last == 0:
            items.pop()
            continue
        if last == (1, 5):  # ga / empty / final
            items.pop()
            continue
        break
    return items


def _compare(left: list[Any], right: list[Any]) -> int:
    size = max(len(left), len(right))
    for index in range(size):
        l_item = left[index] if index < len(left) else None
        r_item = right[index] if index < len(right) else None
        result = _compare_item(l_item, r_item)
        if result:
            return result
    return 0


def _compare_item(left: Any, right: Any) -> int:
    if left is None:
        return -_compare_item(right, None) if right is not None else 0
    if right is None:
        if isinstance(left, int):
            return 0 if left == 0 else 1
        # leftover qualifier vs padding: alpha < ga padding, sp > ga padding
        if isinstance(left, tuple):
            rank = left[1] if isinstance(left[1], int) else 99
            ga = 5
            if isinstance(left[1], int):
                return -1 if rank < ga else (0 if rank == ga else 1)
            return 1
        return 1
    if isinstance(left, int) and isinstance(right, int):
        return (left > right) - (left < right)
    if isinstance(left, int) and isinstance(right, tuple):
        # number vs qualifier: 1.0 > 1.0-alpha (qualifier comes first in 1.0-alpha as leftover)
        return 1
    if isinstance(left, tuple) and isinstance(right, int):
        return -1
    if isinstance(left, tuple) and isinstance(right, tuple):
        return _compare_qual(left, right)
    return 0


def _compare_qual(left: tuple[int, str | int], right: tuple[int, str | int]) -> int:
    l_val = left[1]
    r_val = right[1]
    if isinstance(l_val, int) and isinstance(r_val, int):
        return (l_val > r_val) - (l_val < r_val)
    if isinstance(l_val, int) and isinstance(r_val, str):
        return -1
    if isinstance(l_val, str) and isinstance(r_val, int):
        return 1
    l_text = str(l_val)
    r_text = str(r_val)
    return (l_text > r_text) - (l_text < r_text)
