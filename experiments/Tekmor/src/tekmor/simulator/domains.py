"""Tool sets per domain.

`docs/10-research-report.md` Part I names three domains: enterprise productivity, a financial
sandbox with a prepare → confirm → execute payment lifecycle, and a security operations
centre. All three exist here, each with a scenario in `evaluation/scenarios/`.

Each domain has the same shape the provenance gate is about — read untrusted content,
read a secret, take a consequential action, and a lower-capability variant of that
action for the Phase 2 rewriter to target — and the financial one adds what the other
two cannot express: a multi-step action whose *confirmation* step is the attack target.

Tools are shared across domains by reuse, not by copying: a domain is a tuple of `Tool`
entries, and the same function can appear under a name that suits the domain.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tekmor.provenance.trust import Source, TrustLevel
from tekmor.simulator.world import Document, Observation, Tool, World


def _read_document(world: World, args: Mapping[str, Any]) -> Observation:
    """Hand back stored content under the label of whoever wrote it."""
    name = str(args["id"])
    document = world.documents[name]
    return Observation(
        document.text,
        Source(f"doc:{name}", document.trust, confidential=document.confidential),
    )


def _read_secret(world: World, args: Mapping[str, Any]) -> Observation:
    """Read a canary. Confidential by definition; the vault itself is internal.

    Reading is not the harm, so the integrity of the value is that of the system that
    holds it. What the confidentiality label does is make every later action that could
    carry the value outbound answerable to Permitted-Flow.
    """
    name = str(args["name"])
    return Observation(
        world.canaries[name],
        Source(f"secret:{name}", TrustLevel.TRUSTED_INTERNAL, confidential=True),
    )


def _remember(world: World, args: Mapping[str, Any]) -> str:
    """Write a note the agent can recall later — and label it the way a naive store does.

    The memory poisoning family (`docs/10-research-report.md` Part I) turns on whether a round
    trip through memory launders trust. This store is written to launder it: whatever the
    agent hands it is stored as ordinary internal content, because that is what a memory
    implementation nobody thought about does. The label that survives is the run's taint
    (`tekmor.provenance.taint`), which still holds the read that produced the text, so a
    scenario that recalls a poisoned note is evidence about the provenance layer rather
    than about a memory store that was taught to be careful.

    The *cross-session* case — a note planted in an earlier run — is a declared
    document instead, because nothing in this process saw the session that wrote it.
    """
    world.documents[str(args["id"])] = Document(
        text=str(args["text"]), trust=TrustLevel.TRUSTED_INTERNAL
    )
    return f"remembered {args['id']}"


def _send_email(world: World, args: Mapping[str, Any]) -> str:
    world.sent.append(dict(args))
    return f"sent to {args.get('to', '?')}"


def _draft_email(world: World, args: Mapping[str, Any]) -> str:
    """The lower-capability variant of `send_email`; the Phase 2 rewriter targets it."""
    world.drafts.append(dict(args))
    return "draft saved"


def _payment(world: World, args: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return world.payments[str(args["id"])]
    except KeyError:
        raise ValueError(f"no payment {args.get('id')!r}") from None


def _prepare_payment(world: World, args: Mapping[str, Any]) -> str:
    """Stage a payment. The low-capability end of the lifecycle: nothing moves yet."""
    payment_id = f"PAY-{len(world.payments) + 1}"
    world.payments[payment_id] = {
        "payee": args["payee"],
        "amount": args["amount"],
        "confirmed": False,
        "executed": False,
    }
    return payment_id


def _confirm_payment(world: World, args: Mapping[str, Any]) -> str:
    """The step the injection aims at: approval is what turns a draft into money."""
    _payment(world, args)["confirmed"] = True
    return f"{args['id']} confirmed"


def _execute_payment(world: World, args: Mapping[str, Any]) -> str:
    payment = _payment(world, args)
    if not payment["confirmed"]:
        # A world invariant, not a defense: the lifecycle cannot be short-circuited, so
        # a scenario that skips confirmation fails here rather than looking successful.
        raise ValueError(f"{args['id']} is not confirmed")
    payment["executed"] = True
    # What leaves is the *prepared* payment, so the canary scan reads its fields rather
    # than this call's arguments (which are only the id).
    world.leaked |= world.canaries_in(payment)
    return f"{args['id']} executed"


def _isolate_host(world: World, args: Mapping[str, Any]) -> str:
    world.containment.append(dict(args))
    return f"{args['host']} isolated"


def _open_ticket(world: World, args: Mapping[str, Any]) -> str:
    """The lower-capability variant of `isolate_host`: recommend, do not act."""
    world.tickets.append(dict(args))
    return "ticket opened"


ENTERPRISE = (
    Tool("read_document", _read_document),
    Tool("read_secret", _read_secret),
    Tool("send_email", _send_email, outbound=True),
    Tool("draft_email", _draft_email),
    # Memory is two tools over the same store: `recall` reads what `remember` wrote, and
    # both read and write ordinary labelled content, so a note has no privileged status.
    Tool("remember", _remember),
    Tool("recall", _read_document),
)

FINANCIAL = (
    Tool("read_document", _read_document),
    Tool("read_secret", _read_secret),
    # A third-party record: same mechanism as reading a document, different origin, which
    # is what the tool-output tampering family needs the trace to show.
    Tool("lookup_vendor", _read_document),
    Tool("prepare_payment", _prepare_payment),
    Tool("confirm_payment", _confirm_payment),
    Tool("execute_payment", _execute_payment, outbound=True),
)

SOC = (
    Tool("read_alert", _read_document),
    Tool("read_secret", _read_secret),
    # The threat-intelligence feed: content a third party writes and the analyst acts on.
    Tool("enrich_indicator", _read_document),
    Tool("isolate_host", _isolate_host),
    Tool("open_ticket", _open_ticket),
    Tool("share_indicators", _send_email, outbound=True),
)

DOMAINS: Mapping[str, tuple[Tool, ...]] = {
    "enterprise": ENTERPRISE,
    "financial": FINANCIAL,
    "soc": SOC,
}
