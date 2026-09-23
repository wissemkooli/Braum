"""The trust lattice: ordering and meet."""

import pytest

from tekmor.provenance import TrustLevel, least_trusted


def test_lattice_order_matches_the_documented_order():
    ordered = [
        TrustLevel.ADVERSARY_CONTROLLED,
        TrustLevel.UNTRUSTED_EXTERNAL,
        TrustLevel.UNTRUSTED_INTERNAL,
        TrustLevel.TRUSTED_INTERNAL,
        TrustLevel.AUTHENTICATED_USER,
        TrustLevel.SYSTEM_POLICY,
    ]
    assert ordered == sorted(ordered)
    assert len(TrustLevel) == len(ordered)


@pytest.mark.parametrize(
    ("levels", "expected"),
    [
        ([TrustLevel.SYSTEM_POLICY], TrustLevel.SYSTEM_POLICY),
        (
            [TrustLevel.AUTHENTICATED_USER, TrustLevel.UNTRUSTED_EXTERNAL],
            TrustLevel.UNTRUSTED_EXTERNAL,
        ),
        (
            [TrustLevel.ADVERSARY_CONTROLLED, TrustLevel.SYSTEM_POLICY],
            TrustLevel.ADVERSARY_CONTROLLED,
        ),
    ],
)
def test_meet_is_the_minimum_integrity(levels, expected):
    assert least_trusted(levels) == expected


def test_unknown_provenance_is_not_trusted():
    """No known influences means unknown, and unknown must not read as trusted."""
    assert least_trusted([]) == TrustLevel.ADVERSARY_CONTROLLED
