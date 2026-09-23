"""Taint propagation: what the agent has read, and therefore what drove its next action.

`docs/04-provenance-and-trust.md`: an action's integrity is the
minimum integrity of everything that influenced it. This module computes that set
instead of taking the scenario author's word for it, which is what turns the monitor's
verdicts into evidence about a *system* rather than about hand-declared labels.

The model is the agent's context: an observation the agent has seen is an influence on
every action it proposes afterwards, and it cannot unsee it. So the set only ever grows
within a run, which is also the rule "trust never increases through a round trip through
memory" — a summarised or re-serialized copy of a hostile document is still downstream
of the read that produced it.

ponytail: influence is call-level and prefix-monotone, not field-level. Every observation
the agent has seen taints every later action, so a benign action taken after reading one
hostile document is labelled by that document. That is the conservative direction, and
over-tainting is a real cost (`docs/04-provenance-and-trust.md` §4.4): the benign
halves of the scenario pairs are the check on it.

**Argument-level origins** are the experimental upgrade
(`research/experiments/argument_provenance/`). `TaintTracker.origins` traces each
argument value to the observations whose text contains it verbatim, and a policy with
`argument_provenance` judges Trusted-Action on those origins instead of on the whole
call. A value it cannot trace falls back to call level, so tracing only ever *narrows*
which influences count. It never invents trust for a value nobody supplied.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from tekmor.provenance.trust import ENDORSED, Source, TrustLevel, least_trusted

#: The task itself. It comes from the person who asked for the work, so it is the one
#: influence present before the agent has read anything.
USER_REQUEST = Source("user:request", TrustLevel.AUTHENTICATED_USER, origin="user")


@dataclass(slots=True)
class TaintTracker:
    """The influences accumulated over one run. One tracker per run, never shared.

    Deduplicated by identity of the `Source`, so reading the same document twice is one
    influence, and kept in the order observed so a trace reads as the run happened.
    """

    sources: tuple[Source, ...] = (USER_REQUEST,)
    #: The text of `USER_REQUEST`. Values are traced to it like to any observation.
    request: str = ""
    #: Vouch per field instead of per observation: a source vouches for a value only
    #: when the value *is* one of the fields it returned, never when it merely appears
    #: inside one. `research/experiments/argument_provenance/field_labels.md`.
    field_labels: bool = False
    #: What each observation said, for tracing argument values. Held in memory for the
    #: run only and never logged: it may contain secrets.
    _texts: dict[Source, str] = field(default_factory=dict, repr=False)
    #: The leaf values each observation returned, when the driver could split it into
    #: fields. Empty for a source whose result was unstructured text.
    _fields: dict[Source, set[str]] = field(default_factory=dict, repr=False)
    #: Payload the agent wrote into the world, at the integrity of the call that wrote it.
    _writes: list[tuple[str, TrustLevel]] = field(default_factory=list, repr=False)
    #: Observations that contain a lower-integrity write, and so may not vouch for a value.
    _unvouched: set[Source] = field(default_factory=set, repr=False)

    def observe(self, source: Source, text: str = "", fields: Iterable[str] = ()) -> None:
        """Record that the agent has seen `source`. Influence is never removed.

        `fields` are the leaf values of the structured result, when the driver has it.
        They are what `field_labels` vouching matches against; without them a source
        falls back to matching anywhere in its text, which is the call-level rule.
        """
        if source not in self.sources:
            self.sources = (*self.sources, source)
        self._fields.setdefault(source, set()).update(fields)
        if not text:
            return
        self._texts[source] = f"{self._texts.get(source, '')}\n{text}"
        # Write-back capping. The agent can copy hostile text into a store that labels
        # whatever it is handed as trusted (`remember`, a sent mail). Reading it back must
        # not vouch for anything, or the copy launders the value it carries.
        if any(written in text and level < source.integrity for written, level in self._writes):
            self._unvouched.add(source)

    def wrote(self, args: Mapping[str, Any], content_args: frozenset[str]) -> None:
        """Record the payload an executed call wrote, at the integrity of what drove it.

        Payload is the content arguments. Only those may carry untrusted text past
        argument-level Trusted-Action, so only those can launder it. The integrity is the
        call's, from the raw labels: an endorsement lets content drive the user's request,
        and it must not survive a round trip into a store that is trusted wholesale.
        """
        level = least_trusted(source.trust for source in self.sources)
        for name in content_args & args.keys():
            self._writes += [(leaf, level) for leaf in leaves(args[name]) if leaf is not None]

    def origins(self, args: Mapping[str, Any]) -> tuple[ArgumentOrigin, ...]:
        """For every argument, the observations each of its values was copied from.

        A voucher matches a value anywhere in its text, unless `field_labels` is on and
        the driver split it into fields, in which case the value must *be* one of them.
        The user's request is never split: it is prose the user authored whole, where a
        tool result is a container holding text other principals wrote.
        """
        vouchers = [(USER_REQUEST, self.request, None)] + [
            (source, text, self._fields.get(source) if self.field_labels else None)
            for source, text in self._texts.items()
            if source not in self._unvouched
        ]
        return tuple(
            ArgumentOrigin(
                name,
                tuple(
                    ()
                    if leaf is None
                    else tuple(
                        s
                        for s, text, fields in vouchers
                        if (leaf in fields if fields else leaf in text)
                    )
                    for leaf in leaves(value)
                ),
            )
            for name, value in args.items()
        )


@dataclass(frozen=True, slots=True)
class ArgumentOrigin:
    """Where the values of one argument came from.

    `values` has one entry per leaf value (`leaves`), in order: the observations whose
    text contains that value verbatim and may vouch for it. An empty entry is an
    untraced value, and is judged at call level: a value nobody supplied was produced
    by the agent from everything it had read.
    """

    name: str
    values: tuple[tuple[Source, ...], ...]


#: The shortest argument value that counts as naming something. Below it a value is a
#: word the request may contain by accident ("pay", "all") rather than a resource name.
MIN_NAME = 6


def leaves(value: Any) -> tuple[str | None, ...]:
    """The traceable values inside an argument, `None` for each one that cannot be traced.

    A string, or the text of a number, is traceable when at least `MIN_NAME` characters
    long. Shorter ones match by accident. Lists and mappings contribute their elements.
    A boolean, `None` or anything else is untraceable. It is kept as `None`, never
    dropped, so an argument cannot hide a short hostile value beside a traceable one.
    """
    if isinstance(value, bool) or value is None:
        return (None,)
    if isinstance(value, str | int | float):
        text = str(value)
        return (text if len(text) >= MIN_NAME else None,)
    if isinstance(value, Mapping):
        value = list(value.values())
    if isinstance(value, list | tuple | set | frozenset):
        return tuple(leaf for item in value for leaf in leaves(item))
    return (None,)


def endorse(source: Source, args: Mapping[str, Any], request: str) -> Source:
    """`source`, endorsed by the user if the call that produced it named what they named.

    The endorsement primitive `docs/10-research-report.md` Recommendation 1 asks for once
    utility falls: when the user's authenticated request names a resource verbatim ("pay
    the bill in `bill-december-2023.txt`") and the agent reads exactly that resource, the
    user has vouched for acting on it, and content that was merely *unvouched for* may
    drive the action they asked for. It is a provenance link, not a text classifier:
    what is compared is the read's own argument against the request, never the content.

    It is deliberately narrow. Only `UNTRUSTED_*` content is endorsed — content the
    organization already knows is hostile stays `ADVERSARY_CONTROLLED` whoever names it,
    and trusted content needs nothing. Only integrity moves: confidentiality is
    untouched, so an endorsed read of a secret still may not leave (Permitted-Flow).

    ponytail: "named" is a verbatim match of an argument value of at least `MIN_NAME`
    characters. An attacker who can create a resource whose name is a phrase in the
    request borrows the endorsement for it. The upgrade is structured endorsement — the
    user attaching the resource — which needs an interface this repository does not have.
    """
    if not TrustLevel.UNTRUSTED_EXTERNAL <= source.trust < ENDORSED:
        return source
    named = any(
        isinstance(value, str) and len(value) >= MIN_NAME and value in request
        for value in args.values()
    )
    return replace(source, endorsed_by=USER_REQUEST.id) if named else source
