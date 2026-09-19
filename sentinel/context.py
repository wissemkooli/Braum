"""The provenance ledger: every span of text the agent has seen, and where
it came from.

This is the memory the rest of the defense reasons over. Its one job is to be
able to answer, for any value that shows up in a candidate action:

    "Who wrote this?"

That question -- not "does this text look malicious?" -- is the centre of the
whole design. An identifier that appears *only* inside a vendor's email was
authored by that vendor, whatever the surrounding prose claims.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .normalize import View, canonical, shingles, views
from .trust import Sensitivity, Trust, join_sensitivity, join_trust

_ids = itertools.count(1)

# Values shorter than this are matched as substrings; longer ones by shingle
# overlap, so that a paraphrased or truncated quotation still attributes.
SHORT_VALUE = 64
SHINGLE_HIT = 0.30


@dataclass
class Observation:
    """One field of one tool result, with its provenance labels."""

    obs_id: str
    step: int
    source_ref: str            # e.g. "documents/DOC-3101/body"
    source_kind: str           # document | email | tool_output | memory | alert ...
    trust: Trust
    sensitivity: Sensitivity
    text: str
    derived_from: Tuple[str, ...] = ()   # obs ids this was computed from
    views: Tuple[View, ...] = field(default_factory=tuple, repr=False)
    _shingles: set = field(default_factory=set, repr=False)

    def __post_init__(self):
        if not self.views:
            self.views = tuple(views(self.text))
        if not self._shingles:
            self._shingles = shingles(self.text)

    @property
    def untrusted(self) -> bool:
        return self.trust.untrusted

    def find(self, needle_canon: str) -> Optional[View]:
        """First view of this observation containing `needle_canon`."""
        for view in self.views:
            if needle_canon and needle_canon in canonical(view.text):
                return view
        return None

    def overlap(self, other_shingles: set) -> float:
        if not other_shingles:
            return 0.0
        return len(other_shingles & self._shingles) / len(other_shingles)


@dataclass
class Attribution:
    """Answer to 'who wrote this value?'"""

    value: str
    in_trusted: bool = False
    sources: Tuple[str, ...] = ()          # observation ids that contain it
    transforms: Tuple[str, ...] = ()       # decodings needed to find it
    trust: Trust = Trust.SYSTEM_POLICY
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    resolved: bool = False

    @property
    def untrusted_only(self) -> bool:
        """The decisive predicate: authored by untrusted content, nowhere else.

        The sources must themselves be untrusted. An identifier that first
        appeared in the structured result of a call the guard already approved
        (a freshly minted `REM-0001`) is not attacker-authored, and treating it
        as such blocks the second half of every prepare-then-execute task.
        """
        return (self.resolved and not self.in_trusted and bool(self.sources)
                and self.trust.untrusted)

    @property
    def trusted_origin(self) -> bool:
        return self.resolved and (self.in_trusted or not self.trust.untrusted)

    @property
    def covert(self) -> bool:
        return bool(self.transforms) and "identity" not in self.transforms

    def as_dict(self) -> dict:
        return {
            "in_trusted": self.in_trusted,
            "sources": list(self.sources),
            "transforms": list(self.transforms),
            "trust": self.trust.name,
            "sensitivity": self.sensitivity.name,
            "resolved": self.resolved,
            "untrusted_only": self.untrusted_only,
        }


class ContextLedger:
    """Trusted principal text on one side, everything observed on the other."""

    def __init__(self):
        self.trusted_text: List[Tuple[str, str]] = []   # (label, text)
        self.observations: List[Observation] = []
        self._trusted_canon = ""
        self._trusted_shingles: set = set()

    # ---- population -----------------------------------------------------
    def add_trusted(self, label: str, text: str) -> None:
        """Text from an authoritative principal: the user goal, system policy."""
        self.trusted_text.append((label, text))
        self._trusted_canon = " || ".join(canonical(t) for _, t in self.trusted_text)
        self._trusted_shingles = set()
        for _, t in self.trusted_text:
            self._trusted_shingles |= shingles(t)

    def add_observation(self, **kwargs) -> Observation:
        obs = Observation(obs_id=f"obs-{next(_ids)}", **kwargs)
        self.observations.append(obs)
        return obs

    # ---- queries --------------------------------------------------------
    @property
    def untrusted_observations(self) -> List[Observation]:
        return [o for o in self.observations if o.untrusted]

    @property
    def exposed(self) -> bool:
        """Has any untrusted content entered the context yet?"""
        return bool(self.untrusted_observations)

    def by_id(self, obs_id: str) -> Optional[Observation]:
        return next((o for o in self.observations if o.obs_id == obs_id), None)

    def attribute(self, value) -> Attribution:
        """Find every place a value could have come from.

        Short values (identifiers, statuses, addresses) are matched literally
        against each decoded view; long values by shingle overlap, so quoted
        or lightly edited content still attributes to its source.
        """
        text = "" if value is None else str(value)
        canon = canonical(text)
        att = Attribution(value=text[:200])
        if len(canon) < 2:
            return att

        short = len(canon) <= SHORT_VALUE
        value_shingles = shingles(text) if not short else set()

        if short:
            att.in_trusted = canon in self._trusted_canon
        else:
            hit = len(value_shingles & self._trusted_shingles) / max(1, len(value_shingles))
            att.in_trusted = hit >= SHINGLE_HIT

        sources, transforms, trusts, sens = [], [], [], []
        for obs in self.observations:
            view = obs.find(canon) if short else None
            matched = view is not None
            if not short and obs.overlap(value_shingles) >= SHINGLE_HIT:
                matched, view = True, obs.views[0]
            if not matched:
                continue
            sources.append(obs.obs_id)
            transforms.append(view.transform if view else "identity")
            trusts.append(obs.trust)
            sens.append(obs.sensitivity)

        att.sources = tuple(sources)
        att.transforms = tuple(dict.fromkeys(transforms))
        att.resolved = bool(att.in_trusted or sources)
        att.trust = join_trust(trusts) if trusts else (
            Trust.AUTHENTICATED_USER if att.in_trusted else Trust.UNTRUSTED_EXTERNAL
        )
        att.sensitivity = join_sensitivity(sens) if sens else Sensitivity.PUBLIC
        return att

    def taint_of(self, value) -> List[Tuple[Observation, float]]:
        """Which observations contributed to a piece of content, and how much.

        Used for information-flow checks at sinks: a draft body that overlaps
        a RESTRICTED document is carrying that document, whoever typed it.
        """
        text = "" if value is None else str(value)
        if len(canonical(text)) < 16:
            return []
        value_shingles = shingles(text)
        out = []
        for obs in self.observations:
            share = obs.overlap(value_shingles)
            if share >= 0.10:
                out.append((obs, share))
        return sorted(out, key=lambda pair: -pair[1])

    def untrusted_matching(self, predicate) -> List[Tuple[Observation, View]]:
        """Every (observation, decoded view) pair where `predicate(view_text)`."""
        hits = []
        for obs in self.untrusted_observations:
            for view in obs.views:
                if predicate(view.text):
                    hits.append((obs, view))
                    break
        return hits

    def snapshot(self) -> dict:
        return {
            "observations": len(self.observations),
            "untrusted_observations": len(self.untrusted_observations),
            "worst_trust": join_trust([o.trust for o in self.observations]).name
            if self.observations
            else Trust.SYSTEM_POLICY.name,
            "max_sensitivity_seen": join_sensitivity(
                [o.sensitivity for o in self.observations]
            ).name
            if self.observations
            else Sensitivity.PUBLIC.name,
        }
