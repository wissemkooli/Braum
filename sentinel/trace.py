"""The observability layer's data plane.

Every decision the defense makes writes one structured record here: the
candidate action, the evidence, the weights those pieces of evidence carried,
the score, the intervention, and what happened next. The dashboard and the
terminal replay are both just readers of this file -- there is no second,
prettier version of events.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Tracer:
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    path: Optional[str] = None
    events: List[dict] = field(default_factory=list)
    _fh: Any = field(default=None, repr=False)
    _t0: float = field(default_factory=time.time)

    def __post_init__(self):
        if self.path:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            self._fh = open(self.path, "w", encoding="utf-8")

    def emit(self, kind: str, **fields) -> dict:
        event = {
            "seq": len(self.events),
            "t_ms": round((time.time() - self._t0) * 1000, 2),
            "run_id": self.run_id,
            "kind": kind,
            **fields,
        }
        self.events.append(event)
        if self._fh:
            self._fh.write(json.dumps(event, default=str) + "\n")
            self._fh.flush()
        return event

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def by_kind(self, kind: str) -> List[dict]:
        return [e for e in self.events if e["kind"] == kind]

    def as_dict(self) -> dict:
        return {"run_id": self.run_id, "events": self.events}


def load(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]
