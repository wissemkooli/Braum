"""Encoding-aware detection of a tagged secret in text.

`docs/10-research-report.md` Part I and mechanism 8 (CANARY-FLOW): exfiltration is checked
against *arguments to outbound tools*, and "encoding defeats naive regex" — a base64,
hex, spaced or reversed copy of a token is the same token. CVR is defined as a secret
reaching an outbound argument **in any encoding**, so this module is what makes that
definition true of the measurement as well as of the defense.

It searches for *forms of a known secret* rather than decoding the haystack. The secret
registry is a deployment input, the encodings are few, and generating them is total and
allocation-bounded, where decoding every base64-looking run in a document is neither.

Nothing here is provenance-aware: it reads text and says whether a value is in it. That
is deliberate — it is the residual check for a value that reached an argument *without*
passing through a labelled source, and it is not a replacement for the label
(`tekmor.provenance.trust`). A defense built on this alone is a text matcher, which
`docs/10-research-report.md` Part II is about the failure of.

ponytail: the recognised forms are plain / separator-broken / case-shifted, reversed,
hex, and base64 at each of the three byte alignments. Compositions of two (base64 of the
reversed value, hex with the digits reordered, a value split across two arguments,
gzip+base64) are not recognised. Upgrade path when an adaptive attacker reaches for one:
decode candidate runs in the haystack instead of encoding the needle.
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Mapping
from typing import Any


def _squash(text: str) -> str:
    """Letters and digits only, lowercased.

    Collapses the cheap separators at once: `C A N A R Y`, `c-a-n-a-r-y`, `CaNaRy` and
    `canary` all squash to the same string, so one comparison covers spacing, casing and
    punctuation instead of one rule each.
    """
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _base64_forms(raw: bytes) -> set[str]:
    """The base64 substrings of `raw` that survive being embedded in a larger stream.

    base64 encodes three bytes to four characters, so the encoding of a value depends on
    what byte offset it starts at: `b64encode(secret)` does not appear in
    `b64encode(prefix + secret)` unless `len(prefix) % 3 == 0`. There are only three
    alignments, so all three are generated, and from each only the four-character blocks
    that are determined by `raw` alone are kept — the blocks that share a group with the
    surrounding bytes cannot be predicted and are dropped.
    """
    forms = set()
    for shift in range(3):
        encoded = base64.b64encode(b"\x00" * shift + raw).decode()
        start = 4 * ((shift + 2) // 3)  # first block holding no filler byte
        end = 4 * ((shift + len(raw)) // 3)  # last block `raw` alone determines
        if end > start:
            forms.add(encoded[start:end])
    return forms


def appears_in(secret: str, text: str) -> bool:
    """Whether `secret` is present in `text` in any encoding this scanner recognises.

    An empty secret is never present. A registry entry with no value is a registry bug,
    and treating it as a match would make every call a leak.
    """
    if not secret:
        return False
    plain = _squash(secret)
    if not plain:
        return False
    raw = secret.encode()
    squashed = _squash(text)
    # Hex needs no alignment handling (two characters per byte, no cross-byte state) and
    # is case-insensitive, so it is checked against the squashed text like the rest.
    if plain in squashed or plain[::-1] in squashed or raw.hex() in squashed:
        return True
    # base64 is checked against the raw text: its alphabet is case-significant, and
    # squashing would both lose that and drop `+` and `/`.
    return any(form in text for form in _base64_forms(raw))


def found_in(canaries: Mapping[str, str], values: Iterable[Any]) -> set[str]:
    """The names of the canaries appearing in any one of `values`.

    Each value is searched on its own rather than in a concatenation of all of them: a
    secret is not "present" because its head is in one argument and its tail in the next,
    and joining would report that as a leak.
    """
    texts = [str(value) for value in values]
    return {name for name, value in canaries.items() if any(appears_in(value, t) for t in texts)}
