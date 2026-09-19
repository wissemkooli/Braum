"""Obfuscation-tolerant views of untrusted text.

An attacker who knows a defense reads text will stop writing plain text. The
defense therefore never reasons over a single string: it reasons over a small
*set of decoded views* of the same span, and it remembers which transform
produced each view.

That memory matters. Content that only becomes instruction-shaped after
base64-decoding is far more suspicious than the same instruction in plain
text: benign vendor email does not base64-encode a tool call. The transform
that revealed a signal is itself a signal.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from dataclasses import dataclass
from typing import List

MAX_TEXT = 20000
MAX_VIEWS = 12

_INVISIBLE = re.compile(r"[​-‏‪-‮⁠﻿\xad]")
_B64_TOKEN = re.compile(r"(?:base64[:,]\s*)?([A-Za-z0-9+/]{16,}={0,2})")
_HEX_TOKEN = re.compile(r"(?:0x|hex[:,]\s*)?((?:[0-9a-fA-F]{2}[\s:]?){8,})")
_SPACED = re.compile(r"\b(?:[A-Za-z0-9]\s){3,}[A-Za-z0-9]\b")
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_PRINTABLE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e]+$")


@dataclass(frozen=True)
class View:
    """One decoded view of a span of text."""

    transform: str          # "identity" or the decoding chain that produced it
    text: str
    covert: bool            # True when the view required decoding to read

    @property
    def lowered(self) -> str:
        return self.text.lower()


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 8 or not _PRINTABLE.match(text):
        return None
    # Require some word-like structure, otherwise it is decoding noise.
    if len(re.findall(r"[A-Za-z]{3,}", text)) < 2:
        return None
    return text


def _b64(text: str) -> List[str]:
    out = []
    for token in _B64_TOKEN.findall(text)[:6]:
        padded = token + "=" * (-len(token) % 4)
        try:
            decoded = _printable(base64.b64decode(padded, validate=False))
        except (binascii.Error, ValueError):
            decoded = None
        if decoded:
            out.append(decoded)
    return out


def _hex(text: str) -> List[str]:
    out = []
    for token in _HEX_TOKEN.findall(text)[:4]:
        cleaned = re.sub(r"[\s:]", "", token)
        if len(cleaned) % 2:
            cleaned = cleaned[:-1]
        try:
            decoded = _printable(bytes.fromhex(cleaned))
        except ValueError:
            decoded = None
        if decoded:
            out.append(decoded)
    return out


def _despaced(text: str) -> str | None:
    if not _SPACED.search(text):
        return None
    return _SPACED.sub(lambda m: m.group(0).replace(" ", ""), text)


def _url(text: str) -> str | None:
    if "%" not in text:
        return None
    decoded = urllib.parse.unquote_plus(text)
    return decoded if decoded != text else None


def views(text: str) -> List[View]:
    """Return the identity view plus every decoded view worth considering.

    Cheap and bounded: one decoding pass, at most `MAX_VIEWS` results. The
    goal is not to defeat every possible encoding -- it is to make the cheap
    encodings useless while *recording* that an encoding was used.
    """
    if not text:
        return [View("identity", "", False)]
    text = text[:MAX_TEXT]
    seen = {text}
    out = [View("identity", text, False)]

    stripped = _INVISIBLE.sub("", text)
    if stripped not in seen:
        seen.add(stripped)
        out.append(View("strip_invisible", stripped, True))

    for name, candidate in (
        ("despace", _despaced(stripped)),
        ("urldecode", _url(stripped)),
        ("rot13", codecs.encode(stripped, "rot13") if re.search(r"[A-Za-z]{4,}", stripped) else None),
        ("reverse", stripped[::-1]),
        ("leetspeak", stripped.translate(_LEET)),
    ):
        if candidate and candidate not in seen:
            seen.add(candidate)
            out.append(View(name, candidate, True))

    for decoded in _b64(stripped):
        if decoded not in seen:
            seen.add(decoded)
            out.append(View("base64", decoded, True))
    for decoded in _hex(stripped):
        if decoded not in seen:
            seen.add(decoded)
            out.append(View("hex", decoded, True))

    return out[:MAX_VIEWS]


def canonical(text: str) -> str:
    """Whitespace/case-folded form used for substring and shingle matching."""
    text = _INVISIBLE.sub("", str(text)).lower()
    return re.sub(r"\s+", " ", text).strip()


def shingles(text: str, width: int = 24) -> set:
    """Character n-grams, used to attribute content to the span it came from.

    Stride 1 matters: a sampled stride makes the fingerprint depend on where a
    quotation starts, so the same sentence lifted out of a document would fail
    to match the document it came from.
    """
    canon = canonical(text)
    if len(canon) <= width:
        return {canon} if canon else set()
    return {canon[i : i + width] for i in range(len(canon) - width + 1)}
