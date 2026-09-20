"""Evidence extraction.

Each function below answers one narrow question about a candidate action and
returns `Evidence` if it has something to say. Nothing here decides anything;
`risk.py` weighs the evidence and `policy.py` acts on it.

Signals are grouped into families, and that grouping is load-bearing:

    mandate   does the sealed authority envelope cover this action?
    origin    who authored the values in this action?          (APA)
    context   what kind of text is sitting in the context?
    flow      where is sensitive content about to end up?
    history   what has already happened this turn?

`context` is the only family made of textual heuristics, and its total
contribution is capped (see risk.FAMILY_CAPS) so that a contaminated context
can never by itself stop unrelated legitimate work. The families that carry
the weight -- mandate, origin, flow -- are structural: they do not care how
the attacker phrased anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .capability import Consequence, ToolCatalogue, ToolSpec
from .context import Attribution, ContextLedger
from .mandate import ID_PATTERN, Mandate
from .trust import Sensitivity, Trust

# Encodings whose use is itself evidence: benign content does not base64 a
# tool call. Speculative views (rot13, reverse, leetspeak) are searched for
# attribution but never treated as proof of obfuscation.
REVEALING_TRANSFORMS = ("base64", "hex", "despace", "urldecode")

# ---------------------------------------------------------------------------


@dataclass
class Evidence:
    code: str
    family: str
    strength: float
    rationale: str
    refs: tuple = ()

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "family": self.family,
            "strength": round(self.strength, 3),
            "why": self.rationale,
            "refs": list(self.refs),
        }


@dataclass
class CandidateAction:
    """What the agent wants to do next."""

    tool: str
    args: dict = field(default_factory=dict)
    step: int = 0
    rationale: str = ""

    def clone(self, **kwargs) -> "CandidateAction":
        return CandidateAction(
            tool=kwargs.get("tool", self.tool),
            args=kwargs.get("args", dict(self.args)),
            step=self.step,
            rationale=kwargs.get("rationale", self.rationale),
        )

    def as_dict(self) -> dict:
        return {"tool": self.tool, "args": self.args, "step": self.step}


# ---------------------------------------------------------------- vocabularies

CALL_VERBS = ("call", "invoke", "use", "run", "execute", "trigger", "perform", "issue", "make")

IMPERATIVE_VERBS = (
    "call", "invoke", "execute", "run", "send", "forward", "delete", "disable",
    "reset", "transfer", "pay", "close", "update", "ignore", "disregard",
    "override", "append", "write", "set", "fetch", "read", "visit", "submit",
    "approve", "release", "grant", "remove", "bypass", "skip", "stop", "reply",
)

MODAL_DIRECTIVES = (
    "you must", "you should", "you need to", "you have to", "you are required",
    "it is required that you", "please immediately", "do this now", "your task is",
    "you are instructed", "you will now",
)

REDIRECTION_CUES = (
    "ignore the", "ignore previous", "ignore all", "disregard", "instead of",
    "actually,", "rather than", "forget the", "do not follow", "override the",
    "new instructions", "updated instructions", "stop what",
)

AUTHORITY_TERMS = (
    "policy", "administrator", "admin", "compliance", "directive", "mandate",
    "guardrail", "security team", "it department", "officer", "supervisor",
    "management", "protocol", "regulation", "authorized", "authorised",
)

PERMISSION_GRANTS = (
    "guardrails are disabled", "guardrails have been disabled", "restrictions are lifted",
    "you are permitted", "you may now", "no approval needed", "no approval is needed",
    "pre-approved", "already approved", "has been approved", "is exempt", "bypass the",
    "without human review", "no confirmation required", "override command",
    "disabled by the administrator", "policy 4b", "safety checks are off",
)

JSON_ARGS = re.compile(r"\{[^{}]{0,300}?[\"']?\w+[\"']?\s*:\s*[^{}]{0,300}\}")
ALLCAPS_HEADER = re.compile(r"\b[A-Z][A-Z \-]{7,}\b")


def _call_shape(text: str, tool: str) -> bool:
    """Does this text mention `tool` the way an instruction would?"""
    low = text.lower()
    t = re.escape(tool.lower())
    if re.search(rf"\b(?:{'|'.join(CALL_VERBS)})\s+(?:the\s+)?[`'\"]?{t}\b", low):
        return True
    if re.search(rf"\b{t}\s*\(", low):
        return True
    if re.search(rf"\b{t}\b.{{0,60}}\{{", low, re.S):
        return True
    return False


def _instruction_shape(text: str, catalogue: ToolCatalogue) -> float:
    """How much does this read like an order rather than information? [0,1]"""
    low = text.lower()
    score = 0.0
    if any(m in low for m in MODAL_DIRECTIVES):
        score += 0.35
    if re.search(rf"(?:^|[.\n:;\-]\s*)(?:{'|'.join(IMPERATIVE_VERBS)})\b", low):
        score += 0.25
    if JSON_ARGS.search(text):
        score += 0.20
    if any(_call_shape(text, name) for name in catalogue.names()):
        score += 0.25
    if ALLCAPS_HEADER.search(text):
        score += 0.10
    if re.search(r"\byou\b|\byour\b", low):
        score += 0.10
    return min(1.0, score)


# ------------------------------------------------------------------- families


def dictation_hits(ledger: ContextLedger, tool: str):
    """Untrusted spans that name this tool the way an instruction would."""
    return ledger.untrusted_matching(lambda text: _call_shape(text, tool))


def mandate_signals(
    action: CandidateAction, spec: ToolSpec, effective_capability: str,
    mandate: Mandate, attributions: Dict[str, Attribution], catalogue: ToolCatalogue,
    scoped: bool = False, dictated: bool = False, continuation: bool = False,
) -> List[Evidence]:
    out: List[Evidence] = []
    if spec.always_authorized:
        return out

    if not mandate.capabilities and not mandate.prohibited:
        out.append(Evidence(
            "MANDATE_UNPARSED", "mandate", 1.0,
            "No capability could be derived from the user goal; mandate evidence withheld.",
        ))
        return out

    if mandate.forbids(effective_capability):
        out.append(Evidence(
            "MANDATE_PROHIBITED_CAPABILITY", "mandate", 1.0,
            f"The user explicitly refused this capability ({effective_capability}).",
            (effective_capability,),
        ))
    elif not mandate.authorizes(effective_capability):
        by_severity = {
            Consequence.READ_ONLY: 0.35,
            Consequence.LOCAL_WRITE: 0.55,
            Consequence.PERSISTENT_WRITE: 1.0,
            Consequence.EXTERNAL_EFFECT: 1.0,
            Consequence.IRREVERSIBLE: 1.0,
        }
        strength = by_severity[spec.consequence] * (0.4 if scoped else 1.0)
        # Lifecycle continuation: an agent authorised to *prepare* something was
        # implicitly authorised to finish the thing it prepared. The user who
        # says "prepare the isolation and execute it once I confirm" rarely
        # names the tool family twice. This damps the evidence only -- the
        # confirmation rule for irreversible actions is a hard floor and is
        # untouched, so the human is still asked.
        if continuation:
            strength *= 0.15
        out.append(Evidence(
            "MANDATE_CAPABILITY_EXPANSION", "mandate", strength,
            f"{effective_capability} is outside the authority sealed from the user goal "
            f"({', '.join(sorted(mandate.capabilities)) or 'none'}).",
            (effective_capability, mandate.seal),
        ))

    # Targets: which record is being acted on?
    off_target = []
    for arg in spec.args_with_role("target"):
        value = str(action.args.get(arg, "")).strip()
        if not value or not ID_PATTERN.fullmatch(value):
            continue
        if value in mandate.resources:
            continue
        # Identifiers produced by an earlier approved step are part of the task,
        # not a detour away from it.
        att = attributions.get(arg)
        if att is not None and att.trusted_origin:
            continue
        off_target.append((arg, value))
    open_family = mandate.resource_open(spec.family)
    if off_target:
        strength = 0.25 if open_family else 0.9
        if spec.consequence == Consequence.READ_ONLY and not dictated:
            strength = min(strength, 0.35)
        out.append(Evidence(
            "TARGET_OUTSIDE_MANDATE", "mandate", strength,
            f"Acts on {', '.join(v for _, v in off_target)}, which the user never named "
            + ("(the goal referred to the record indirectly, so some resolution is expected)."
               if open_family else f"(goal named: {', '.join(sorted(mandate.resources)) or 'nothing'})."),
            tuple(v for _, v in off_target),
        ))

    # An identifier the user referred to indirectly ("the corresponding ticket")
    # is *meant* to be resolved out of content, so it does not void the mandate.
    if (
        mandate.authorizes(effective_capability)
        and (not off_target or open_family)
        and not mandate.forbids(effective_capability)
    ):
        out.append(Evidence(
            "IN_MANDATE", "mandate", 1.0,
            f"{effective_capability} on a record the user named is inside the sealed mandate.",
            (mandate.seal,),
        ))
    return out


def origin_signals(
    action: CandidateAction, spec: ToolSpec, ledger: ContextLedger,
    mandate: Mandate, attributions: Dict[str, Attribution], catalogue: ToolCatalogue,
    dictated: bool = False,
) -> List[Evidence]:
    """Argument Provenance Attribution: who authored this action?"""
    out: List[Evidence] = []
    role_weight = {"control": 1.0, "target": 0.85, "content": 0.15}
    if mandate.resource_open(spec.family):
        role_weight["target"] = 0.25
    # Following a reference found in content is how investigation works: an
    # analyst triaging an alert looks up the domain the alert names, and there
    # is no provenance difference between that and a malicious redirect.
    # What *does* separate them is whether the content issued an instruction
    # naming this tool. So a read is cheap only while nothing told the agent to
    # make it; the moment the content dictates the call, full weight returns.
    if spec.consequence == Consequence.READ_ONLY and not dictated:
        role_weight["target"] = min(role_weight["target"], 0.30)

    decisive_args = [a for a in action.args if spec.role_of(a) in ("control", "target")]
    graded, covert, unresolved, trusted = [], [], [], []

    for arg, att in attributions.items():
        role = spec.role_of(arg)
        if att.untrusted_only:
            graded.append((arg, role, role_weight.get(role, 0.5), att))
            if att.covert:
                covert.append((arg, att))
        elif not att.resolved and role in ("control", "target"):
            unresolved.append(arg)
        elif att.in_trusted:
            trusted.append(arg)

    if graded:
        best = max(graded, key=lambda g: g[2])
        detail = "; ".join(
            f"{arg} = {att.value!r} appears only in {', '.join(att.sources)} "
            f"({att.trust.name})" for arg, _, _, att in sorted(graded, key=lambda g: -g[2])[:3]
        )
        out.append(Evidence(
            "ARG_UNTRUSTED_ORIGIN", "origin", best[2],
            f"{best[1].capitalize()} argument authored by observed content, not by the user: {detail}",
            tuple(arg for arg, *_ in graded),
        ))

    if covert:
        transforms = sorted({t for _, att in covert for t in att.transforms if t != "identity"})
        # A value recoverable only after a real decoding is strong evidence;
        # one that merely happens to appear in a speculative view is weak.
        deliberate = any(t in REVEALING_TRANSFORMS for t in transforms)
        out.append(Evidence(
            "ARG_COVERT_ORIGIN", "origin", 1.0 if deliberate else 0.4,
            f"Argument value was only recoverable from observed content after decoding "
            f"({', '.join(transforms) or 'encoded'}) -- benign content does not encode tool arguments.",
            tuple(arg for arg, _ in covert),
        ))

    if unresolved:
        out.append(Evidence(
            "ARG_UNRESOLVED_ORIGIN", "origin", 0.3,
            f"No source in trusted goal or observed content for: {', '.join(unresolved)}.",
            tuple(unresolved),
        ))

    if decisive_args and not graded and not unresolved and trusted:
        out.append(Evidence(
            "TRUSTED_ORIGIN", "origin", 1.0,
            "Every decisive argument traces back to the user's own words.",
            tuple(trusted),
        ))
    elif not decisive_args and not graded:
        out.append(Evidence(
            "TRUSTED_ORIGIN", "origin", 0.6,
            "The action carries no attacker-reachable target or control argument.",
        ))

    # Direct dictation: untrusted text that names this very tool in call shape.
    hits = dictation_hits(ledger, action.tool)
    if hits:
        arg_overlap = max(
            [role_weight.get(spec.role_of(a), 0.3) for a, att in attributions.items()
             if att.untrusted_only and any(s in [o.obs_id for o, _ in hits] for s in att.sources)],
            default=0.0,
        )
        strength = max(0.30, arg_overlap)
        obs, view = hits[0]
        out.append(Evidence(
            "UNTRUSTED_ACTION_DICTATION", "origin", strength,
            f"{obs.source_ref} ({obs.trust.name}) instructs a call to {action.tool}"
            + (f" (visible only after {view.transform} decoding)" if view.covert else "")
            + ("; it also supplies this call's arguments." if arg_overlap >= 0.85 else "."),
            tuple(o.obs_id for o, _ in hits),
        ))
    return out


def context_signals(ledger: ContextLedger, catalogue: ToolCatalogue) -> List[Evidence]:
    """Textual heuristics about the context as a whole. Capped contribution."""
    out: List[Evidence] = []
    if not ledger.exposed:
        out.append(Evidence(
            "NO_UNTRUSTED_EXPOSURE", "history", 1.0,
            "No untrusted content has entered the context; nothing could have induced this action.",
        ))
        return out

    best_instruction, best_ref, best_view = 0.0, None, None
    covert_instruction = None
    redirection, authority, grants = None, None, None

    for obs in ledger.untrusted_observations:
        for view in obs.views:
            score = _instruction_shape(view.text, catalogue)
            if score > best_instruction:
                best_instruction, best_ref, best_view = score, obs, view
            if (view.covert and view.transform in REVEALING_TRANSFORMS
                    and score >= 0.5 and covert_instruction is None):
                covert_instruction = (obs, view)
            low = view.text.lower()
            if redirection is None and any(c in low for c in REDIRECTION_CUES):
                redirection = (obs, view)
            if grants is None and any(g in low for g in PERMISSION_GRANTS):
                grants = (obs, view)
            if authority is None and any(a in low for a in AUTHORITY_TERMS) and score >= 0.3:
                authority = (obs, view)

    if best_instruction >= 0.25:
        out.append(Evidence(
            "IMPERATIVE_IN_UNTRUSTED", "context", best_instruction,
            f"{best_ref.source_ref} contains text shaped like an instruction rather than information.",
            (best_ref.obs_id,),
        ))
    if covert_instruction:
        obs, view = covert_instruction
        out.append(Evidence(
            "OBFUSCATED_INSTRUCTION", "context", 1.0,
            f"{obs.source_ref} hides instruction-shaped text behind {view.transform} encoding.",
            (obs.obs_id,),
        ))
    if redirection:
        obs, _ = redirection
        out.append(Evidence(
            "GOAL_REDIRECTION", "context", 0.9,
            f"{obs.source_ref} tries to replace the user's goal with another one.",
            (obs.obs_id,),
        ))
    if grants or authority:
        obs, _ = grants or authority
        out.append(Evidence(
            "AUTHORITY_FORGERY", "context", 1.0 if grants else 0.6,
            f"{obs.source_ref} claims policy or administrative authority, but arrives over a "
            f"{obs.trust.name} channel that carries no authority at all.",
            (obs.obs_id,),
        ))
    return out


# Sinks that leave the organisation. Content reaching these is disclosure;
# content written into an internal record is filing.
EXTERNAL_SINKS = ("outbound", "external", "public")


def flow_signals(
    action: CandidateAction, spec: ToolSpec, ledger: ContextLedger, mandate: Mandate,
) -> List[Evidence]:
    """Where is content about to end up, and where did it come from?"""
    out: List[Evidence] = []
    if not spec.sink:
        return out
    external_sink = any(marker in spec.sink for marker in EXTERNAL_SINKS)

    worst: Optional[tuple] = None
    unauthorized_source = None
    for arg in spec.args_with_role("content") + spec.args_with_role("control"):
        value = action.args.get(arg)
        secret_holders = {o.obs_id for o, _ in ledger.secrets_carried(value)}
        for obs, share in ledger.taint_of(value):
            ids = set(ID_PATTERN.findall(obs.source_ref))
            off_mandate = bool(ids) and not (ids & set(mandate.resources)) and not mandate.resource_open(spec.family)
            # A RESTRICTED credential is not something any sink receives by
            # default -- the user's reply included -- unless the user named
            # the record it lives in.
            bare_secret = (obs.obs_id in secret_holders
                           and obs.sensitivity >= Sensitivity.RESTRICTED
                           and not (ids & set(mandate.resources)))
            if obs.sensitivity >= Sensitivity.CONFIDENTIAL and (external_sink or off_mandate or bare_secret):
                if worst is None or obs.sensitivity > worst[1].sensitivity:
                    worst = (arg, obs, share)
            if off_mandate:
                unauthorized_source = unauthorized_source or (arg, obs)

    if worst:
        arg, obs, share = worst
        strength = 1.0 if obs.sensitivity >= Sensitivity.RESTRICTED else 0.8
        carried = (f"`{arg}` carries a credential-shaped token verbatim from"
                   if obs.obs_id in {o.obs_id for o, _ in ledger.secrets_carried(action.args.get(arg))}
                   else f"{int(share * 100)}% of `{arg}` traces to")
        out.append(Evidence(
            "EXFIL_SENSITIVE_TO_SINK", "flow", strength,
            f"{carried} {obs.source_ref} "
            f"({obs.sensitivity.name}), heading for the `{spec.sink}` sink.",
            (obs.obs_id, arg),
        ))
    if unauthorized_source:
        arg, obs = unauthorized_source
        out.append(Evidence(
            "FLOW_UNAUTHORIZED_SOURCE", "flow", 0.7,
            f"`{arg}` carries content from {obs.source_ref}, a record outside the sealed mandate.",
            (obs.obs_id, arg),
        ))
    return out


def history_signals(session_state: dict) -> List[Evidence]:
    out: List[Evidence] = []
    intercepted = session_state.get("intercepted", 0)
    if intercepted:
        out.append(Evidence(
            "CONTAMINATION_PRESSURE", "history", min(1.0, intercepted / 3.0),
            f"{intercepted} action(s) already intercepted this turn: the context is actively "
            f"pushing the agent off-mandate.",
        ))
    return out
