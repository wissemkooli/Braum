"""Taint propagation: what the agent has read, and what that makes its next action."""

from tekmor.defense import ActionProvenance
from tekmor.provenance import USER_REQUEST, Source, TaintTracker, TrustLevel

HOSTILE = Source("doc:INV-91", TrustLevel.ADVERSARY_CONTROLLED, origin="read_document")
SECRET = Source("secret:portal_token", TrustLevel.TRUSTED_INTERNAL, confidential=True)


def test_a_run_starts_with_the_request_that_asked_for_it():
    # Before the agent has read anything, the one influence on it is the person who
    # asked. Starting empty would read as `ADVERSARY_CONTROLLED` and block the first
    # sensitive step of every benign run.
    assert TaintTracker().sources == (USER_REQUEST,)
    assert ActionProvenance.of(TaintTracker().sources).integrity is TrustLevel.AUTHENTICATED_USER


def test_reading_hostile_content_lowers_every_later_action():
    taint = TaintTracker()
    taint.observe(HOSTILE)
    assert ActionProvenance.of(taint.sources).integrity is TrustLevel.ADVERSARY_CONTROLLED


def test_influence_is_never_removed_by_reading_something_trustworthy():
    # Trust never increases through a round trip: a hostile document summarised, quoted
    # or followed by clean work is still upstream of everything the agent does next.
    taint = TaintTracker()
    taint.observe(HOSTILE)
    taint.observe(Source("tool:draft_email", TrustLevel.TRUSTED_INTERNAL))
    assert ActionProvenance.of(taint.sources).integrity is TrustLevel.ADVERSARY_CONTROLLED


def test_the_same_source_twice_is_one_influence():
    taint = TaintTracker()
    taint.observe(HOSTILE)
    taint.observe(HOSTILE)
    assert taint.sources == (USER_REQUEST, HOSTILE)


def test_confidentiality_travels_separately_from_integrity():
    # Reading a secret does not lower integrity, and reading a hostile document does not
    # make the run confidential. Collapsing the two would lose one of the two rules.
    taint = TaintTracker()
    taint.observe(SECRET)
    provenance = ActionProvenance.of(taint.sources)
    assert provenance.confidential is True
    assert provenance.integrity is TrustLevel.TRUSTED_INTERNAL


def test_trackers_do_not_share_state():
    # The default is a class attribute on a slotted dataclass; one run's reads must not
    # become another's.
    first = TaintTracker()
    first.observe(HOSTILE)
    assert TaintTracker().sources == (USER_REQUEST,)
