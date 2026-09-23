"""Per-domain policy data, and the deterministic rules evaluated over it.

`docs/10-research-report.md` Part IV and Part VII: the policy engine enforces two rules
before any tool call.

**Trusted-Action** — a sensitive tool may only be driven by inputs whose minimum
integrity is at least the policy threshold.
**Permitted-Flow** — confidential data may not leave through an outbound call unless
every recipient is authorized.

Both are pure predicates over primitives, not over the defense's types: the policy
engine must be testable, replayable and property-testable on its own, and taking
`Action`/`ActionProvenance` here would make `policy` import `defense`, which imports
`policy`. Turning a violation into ALLOW / REWRITE / ESCALATE / BLOCK is the decision
core's job (`tekmor.defense.monitor`), not this module's.

Policies are data. Nothing here reads a clock, a network, or a model, so the same
policy and the same inputs always produce the same answer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from tekmor.provenance.trust import TrustLevel


@dataclass(frozen=True, slots=True)
class Policy:
    """The active policy for one domain.

    Tool sensitivity lives here rather than on a tool definition because it is a
    per-domain judgement: the same `send_email` tool is routine in one deployment and
    restricted in another. `outbound_tools` is the exception in spirit — where a tool
    sends data is intrinsic to the tool — but the defense is handed only a policy, never
    the world, so the policy carries the fact. The scenario loader fills it in from the
    domain's own tool specs so the two cannot drift.

    `allowed_tools` is least privilege and has no permissive default: a tool is not
    permitted because nobody mentioned it.
    """

    name: str
    sensitive_tools: frozenset[str] = frozenset()
    allowed_tools: frozenset[str] = frozenset()
    outbound_tools: frozenset[str] = frozenset()
    #: Trusted-Action threshold: the minimum integrity that may drive a sensitive tool.
    min_integrity: TrustLevel = TrustLevel.TRUSTED_INTERNAL
    authorized_recipients: frozenset[str] = frozenset()
    #: Argument names that name a destination. Per-domain because the tools differ.
    recipient_args: frozenset[str] = frozenset({"to"})
    #: Impact-ordered capability lattice: risky tool -> its lower-capability variant.
    rewrites: Mapping[str, str] = field(default_factory=dict)
    #: Endorse content the user named verbatim in the request (`provenance.taint.endorse`).
    #: Off unless a deployment turns it on: it is the one way trust is ever raised.
    endorse_named: bool = False
    #: Judge Trusted-Action on the provenance of each argument instead of the whole call
    #: (`provenance.taint.ArgumentOrigin`). Off by default: it is an experiment,
    #: `research/experiments/argument_provenance/`.
    argument_provenance: bool = False
    #: Argument names that carry payload (a body, a subject, a note). Untrusted content
    #: may fill them, so argument-level Trusted-Action does not judge them.
    #: Confidentiality still does: Permitted-Flow is unchanged.
    content_args: frozenset[str] = frozenset()
    #: Argument names that name a destination, a principal or a credential. Unless
    #: `endorse_targets` is set, endorsement never raises them: the user vouching for a
    #: document lets its content drive their request, not its addresses.
    target_args: frozenset[str] = frozenset()
    endorse_targets: bool = False
    version: int = 1


def permitted_tool(tool: str, policy: Policy) -> bool:
    """Least privilege: is `tool` permitted at all under this policy?"""
    return tool in policy.allowed_tools


def trusted_action(tool: str, integrity: TrustLevel, policy: Policy) -> bool:
    """Trusted-Action: may inputs of this minimum integrity drive `tool`?

    A non-sensitive tool passes whatever drove it. That is deliberate and is the
    "untrusted is not irrelevant" property: the agent must be able to read hostile
    content without the read itself becoming a violation.
    """
    return tool not in policy.sensitive_tools or integrity >= policy.min_integrity


def permitted_flow(
    tool: str,
    confidential: bool,
    recipients: Iterable[str],
    policy: Policy,
) -> bool:
    """Permitted-Flow: may confidential data leave through this call?

    Confidentiality is carried by the provenance of the action, not by matching the
    secret's text in the arguments. That is the whole point: an encoded, paraphrased or
    re-serialized copy of a secret has the same provenance as the original, so this rule
    does not care which encoding the argument is in.

    An outbound call with no recognisable recipient is not permitted. The destination
    cannot be checked, and an unverifiable destination must not read as an authorized
    one.
    """
    if not confidential or tool not in policy.outbound_tools:
        return True
    destinations = tuple(recipients)
    return bool(destinations) and all(d in policy.authorized_recipients for d in destinations)


def recipients_of(args: Mapping[str, Any], policy: Policy) -> tuple[str, ...]:
    """The destinations named in `args`, according to the policy's recipient arguments."""
    return tuple(str(args[name]) for name in sorted(policy.recipient_args) if name in args)


def downgrade_for(tool: str, policy: Policy) -> str | None:
    """The lower-capability variant of `tool`, if the policy declares a safe one.

    The declared target is vetted rather than trusted. A rewrite that pointed at a tool
    which is itself sensitive, outbound, or not permitted would turn a refused action
    into an executed one, so a policy typo fails closed here: no downgrade, and the
    caller escalates instead.
    """
    target = policy.rewrites.get(tool)
    if target is None or not permitted_tool(target, policy):
        return None
    if target in policy.sensitive_tools or target in policy.outbound_tools:
        return None
    return target
