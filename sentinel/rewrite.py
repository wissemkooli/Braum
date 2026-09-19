"""Safer substitutions.

Blocking is a blunt instrument and a costly one: a defense that refuses the
whole action also refuses the legitimate part of it. The poisoned ticket
update in the AgentDojo scenario is the clearest case -- the agent is supposed
to update that ticket; it is only the `status: closed` argument that the
attacker wrote. Dropping one argument keeps the task and kills the attack.

Three strategies, tried cheapest-first:

    quarantine  drop the arguments that untrusted content authored
    redact      strip sensitive spans out of content headed for a sink
    downgrade   substitute the declared safer tool (send -> draft)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List

from .capability import ToolSpec
from .context import Attribution, ContextLedger
from .mandate import Mandate
from .normalize import shingles
from .signals import CandidateAction
from .trust import Sensitivity

REDACTION = "[redacted by SENTINEL: content classified above this task's mandate]"
SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass
class Rewrite:
    strategy: str
    action: CandidateAction
    description: str

    def as_dict(self) -> dict:
        return {"strategy": self.strategy, "action": self.action.as_dict(), "description": self.description}


def quarantine_untrusted_args(
    action: CandidateAction, spec: ToolSpec, attributions: Dict[str, Attribution]
) -> List[Rewrite]:
    """Drop attacker-authored control arguments, keep the rest of the call."""
    dropped = [
        arg
        for arg, att in attributions.items()
        if att.untrusted_only
        and spec.role_of(arg) == "control"
        and arg not in spec.required_args
    ]
    if not dropped:
        return []
    args = {k: v for k, v in action.args.items() if k not in dropped}
    if not all(r in args for r in spec.required_args):
        return []
    return [Rewrite(
        "quarantine",
        action.clone(args=args),
        f"Removed {', '.join(dropped)} -- authored by observed content, not by the user. "
        f"The rest of the call is the user's own request and proceeds.",
    )]


def redact_sensitive_content(
    action: CandidateAction, spec: ToolSpec, ledger: ContextLedger, mandate: Mandate
) -> List[Rewrite]:
    """Strip spans that came from records above the mandate's clearance."""
    if not spec.sink:
        return []
    args = dict(action.args)
    removed = []
    for arg in spec.args_with_role("content"):
        value = args.get(arg)
        if not isinstance(value, str) or len(value) < 16:
            continue
        sensitive = [
            obs for obs, _ in ledger.taint_of(value)
            if obs.sensitivity >= Sensitivity.CONFIDENTIAL
        ]
        if not sensitive:
            continue
        kept = []
        for piece in SENTENCE.split(value):
            grains = shingles(piece)
            if grains and any(
                len(grains & obs._shingles) / len(grains) >= 0.30 for obs in sensitive
            ):
                removed.append(obs.source_ref for obs in sensitive)
                continue
            kept.append(piece)
        cleaned = " ".join(p for p in kept if p.strip()).strip()
        args[arg] = (cleaned + " " + REDACTION).strip() if cleaned else REDACTION
        removed.append(arg)
    if not removed:
        return []
    refs = sorted({o.source_ref for arg in spec.args_with_role("content")
                   for o, _ in ledger.taint_of(action.args.get(arg))
                   if o.sensitivity >= Sensitivity.CONFIDENTIAL})
    return [Rewrite(
        "redact",
        action.clone(args=args),
        f"Removed content originating from {', '.join(refs)} before it reaches the "
        f"`{spec.sink}` sink; the rest of the message is unchanged.",
    )]


def downgrade(action: CandidateAction, spec: ToolSpec) -> List[Rewrite]:
    """Substitute the declared safer capability, e.g. send -> draft."""
    if not spec.safer_alternative:
        return []
    alt = spec.safer_alternative
    # `keep` names the arguments that certainly carry over; anything else the
    # original call had is preserved too, because the safer tool in the same
    # family generally accepts the same schema and silently dropping a required
    # argument turns a rewrite into a failed call.
    args = dict(action.args) if not alt.keep else {
        k: v for k, v in action.args.items() if k in alt.keep or k in spec.args
    }
    return [Rewrite(
        "downgrade",
        action.clone(tool=alt.tool, args=args),
        f"Substituted {alt.tool} for {action.tool}: the work is preserved in a reversible "
        f"form and a human decides whether it goes further.",
    )]


def candidates(
    action: CandidateAction, spec: ToolSpec, attributions: Dict[str, Attribution],
    ledger: ContextLedger, mandate: Mandate,
) -> List[Rewrite]:
    out = quarantine_untrusted_args(action, spec, attributions)
    out += redact_sensitive_content(action, spec, ledger, mandate)
    out += downgrade(action, spec)
    return out
