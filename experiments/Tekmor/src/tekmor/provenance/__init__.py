"""Tekmor provenance component: the trust lattice, labelled sources, and taint.

See docs/03-architecture.md.
"""

from tekmor.provenance.canary import appears_in, found_in
from tekmor.provenance.taint import USER_REQUEST, TaintTracker
from tekmor.provenance.trust import Source, TrustLevel, least_trusted

__all__ = [
    "USER_REQUEST",
    "Source",
    "TaintTracker",
    "TrustLevel",
    "appears_in",
    "found_in",
    "least_trusted",
]
