"""Trust and sensitivity lattices.

Every observation the agent makes carries three things: where it came from,
how sensitive it is, and how far it may be trusted. Those labels are the
substrate every other part of the defense reasons over.

Both lattices are total orders, joined by `max` on the pessimistic side:
combining two pieces of content yields the *least* trusted and the *most*
sensitive of its parts.
"""

from __future__ import annotations

from enum import IntEnum
from typing import Iterable


class Trust(IntEnum):
    """Provenance trust. Lower value == more trusted."""

    SYSTEM_POLICY = 0
    AUTHENTICATED_USER = 1
    TRUSTED_INTERNAL = 2
    UNTRUSTED_INTERNAL = 3
    UNTRUSTED_EXTERNAL = 4
    ADVERSARY_CONTROLLED = 5

    @property
    def authoritative(self) -> bool:
        """May content at this level *instruct* the agent (vs. inform it)?"""
        return self <= Trust.AUTHENTICATED_USER

    @property
    def untrusted(self) -> bool:
        return self >= Trust.UNTRUSTED_INTERNAL


class Sensitivity(IntEnum):
    """Disclosure sensitivity. Higher value == more damaging to leak."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


def parse_trust(value, default: Trust = Trust.UNTRUSTED_EXTERNAL) -> Trust:
    if isinstance(value, Trust):
        return value
    if value is None:
        return default
    try:
        return Trust[str(value).strip().upper()]
    except KeyError:
        return default


def parse_sensitivity(value, default: Sensitivity = Sensitivity.INTERNAL) -> Sensitivity:
    if isinstance(value, Sensitivity):
        return value
    if value is None:
        return default
    try:
        return Sensitivity[str(value).strip().upper()]
    except KeyError:
        return default


def join_trust(levels: Iterable[Trust]) -> Trust:
    """Pessimistic join: a mixture is only as trustworthy as its worst part."""
    levels = list(levels)
    return max(levels) if levels else Trust.SYSTEM_POLICY


def join_sensitivity(levels: Iterable[Sensitivity]) -> Sensitivity:
    """Pessimistic join: a mixture is as sensitive as its most sensitive part."""
    levels = list(levels)
    return max(levels) if levels else Sensitivity.PUBLIC
