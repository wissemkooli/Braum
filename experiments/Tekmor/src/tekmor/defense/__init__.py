"""Tekmor defense component: the decision contract, the monitor, and the baselines.

`ReferenceMonitor` is the deterministic core of Proposal A: least privilege,
Permitted-Flow, then Trusted-Action with a capability downgrade. It decides from the
named `Signals` that `signals.extract` computes, and reports the `risk` score
`risk.score` derives from that same object — the rules decide, the score describes; see
`defense/risk.py`.

`CanaryScanner` layers the encoding-aware secret scan (CANARY-FLOW) over any defense,
for the argument-level residual the provenance rule cannot see, and `AlignmentAuditor`
(Proposal B) asks a judge about the gray-zone actions the rules allowed. Both only raise.
"""

from tekmor.defense.auditor import AlignmentAuditor, Judge
from tekmor.defense.canary import CanaryScanner
from tekmor.defense.core import (
    Action,
    ActionProvenance,
    AgentState,
    Decision,
    Defense,
    Source,
    Verdict,
    mediate,
)
from tekmor.defense.monitor import ReferenceMonitor
from tekmor.defense.risk import band, contributions
from tekmor.defense.risk import score as risk_score
from tekmor.defense.signals import Signals, extract

__all__ = [
    "Action",
    "AlignmentAuditor",
    "CanaryScanner",
    "ActionProvenance",
    "AgentState",
    "Decision",
    "Defense",
    "Judge",
    "ReferenceMonitor",
    "Signals",
    "Source",
    "Verdict",
    "band",
    "contributions",
    "extract",
    "mediate",
    "risk_score",
]
