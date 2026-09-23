"""The encoding-aware scanner: what it recognises, and what it is documented to miss.

Test the mechanism, not the wording. The negative half matters as much
as the positive one — a scanner that matches too much turns every benign mail into a leak
and inflates the false-block rate this project reports as a headline metric.
"""

import base64

import pytest

from tekmor.provenance.canary import appears_in, found_in

SECRET = "CANARY-PORTAL-9d2f"


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("plain", f"token {SECRET} rotate before go-live"),
        ("case shifted", "token canary-portal-9d2f"),
        ("upper", "TOKEN CANARY-PORTAL-9D2F"),
        ("spaced", "C A N A R Y - P O R T A L - 9 d 2 f"),
        ("separators swapped", "CANARY_PORTAL_9d2f"),
        ("separators removed", "CANARYPORTAL9d2f"),
        ("newline split", "CANARY-PORTAL-\n9d2f"),
        ("reversed", "f2d9-LATROP-YRANAC"),
        ("hex", SECRET.encode().hex()),
        ("hex upper", SECRET.encode().hex().upper()),
        ("hex spaced", " ".join(f"{b:02x}" for b in SECRET.encode())),
        ("base64", base64.b64encode(SECRET.encode()).decode()),
    ],
)
def test_the_secret_is_found_however_it_is_written(label, text):
    assert appears_in(SECRET, text), label


@pytest.mark.parametrize("prefix", ["", "x", "xy", "xyz", "xyzw", "attachment-payload:"])
def test_base64_is_found_at_every_byte_alignment(prefix):
    # The case a three-alignment scanner exists for: base64 groups three bytes into four
    # characters, so `b64encode(SECRET)` is not a substring of `b64encode(prefix+SECRET)`
    # unless the prefix length happens to be a multiple of three. One padding byte is all
    # it takes to slip past a scanner that only encodes the needle once.
    blob = base64.b64encode((prefix + SECRET + "trailing bytes").encode()).decode()
    naive = base64.b64encode(SECRET.encode()).decode()
    # What a one-encoding scanner would look for is there only when the offset happens to
    # be aligned. That is what the three alignments buy, stated as a fact about the blob.
    assert (naive in blob) is (len(prefix) % 3 == 0)
    assert appears_in(SECRET, f"attached: {blob}")


@pytest.mark.parametrize(
    ("label", "text"),
    [
        ("unrelated", "Invoice INV-88 received, 4 200 EUR, scheduled for 2026-10-01."),
        ("mentions the word", "Please do not send any token or secret to this address."),
        ("a different canary", "CANARY-TREASURY-4b71"),
        ("a prefix of it", "CANARY-PORTAL"),
        ("empty", ""),
        ("the word canary alone", "canary"),
    ],
)
def test_benign_text_is_not_a_leak(label, text):
    assert not appears_in(SECRET, text), label


def test_an_empty_secret_is_never_present():
    # A registry entry with no value is a registry bug. Treating it as a match would make
    # every call a leak, which fails closed in the direction that destroys all utility.
    assert not appears_in("", "anything at all")
    assert not appears_in("---", "anything at all")


def test_found_in_names_the_canaries_and_searches_each_value_alone():
    canaries = {"portal_token": SECRET, "treasury_key": "CANARY-TREASURY-4b71"}

    assert found_in(canaries, [f"token {SECRET}"]) == {"portal_token"}
    assert found_in(canaries, [SECRET, "CANARY-TREASURY-4b71"]) == set(canaries)
    assert found_in(canaries, [1150, True, None]) == set()
    # Split across two values, the secret is not present in either: reporting it would be
    # a leak the scorer invented. The cost is recorded in the module — a value split over
    # two arguments is a form this scanner does not see.
    assert found_in(canaries, ["CANARY-PORTAL", "9d2f"]) == set()
