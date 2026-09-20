"""Record the dashboard's trace for runs driven through the v1 HTTP API.

The organizers' harness owns the loop in every run against the Qwen3-8B
reference agent, so the defense only ever sees one `DefenseRequest` at a time,
and the adapter deliberately rebuilds the guard from each request. A tracer
handed to it directly would re-announce the mandate and every observation at
every step.

This recorder handles that. Each request is decided with an in-memory
tracer, and only what is *new* for that run is appended to
`<trace_dir>/<run_id>.jsonl`: the mandate when it changes (a new turn),
observations not yet recorded, the agent's intent, the full decision record,
and -- from the next request's history digest -- what the harness did with the
previous decision. `sentinel replay` and `sentinel dashboard` read the file.

It is observability only. Nothing recorded here is read back by the decision
path, and the run id is used as a filename and a label, never as an input.

`attach_outcome` folds the harness's own end-of-run events (tool errors, human
confirmations, policy findings, task success) into a recorded trace afterwards,
so the dashboard can show the verdict next to the decisions.
"""

from __future__ import annotations

import json
import os
import re
import threading
from typing import Dict, List, Optional

from sentinel.api_adapter import action_digest, decide
from sentinel.trace import Tracer, load

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
OBS_ID = re.compile(r"\bobs-\d+\b")


class _Run:
    def __init__(self, path: str):
        self.tracer = Tracer(path=path)
        self.seal: Optional[str] = None
        self.turn = -1
        self.observations: Dict[tuple, str] = {}   # content key -> stable id
        self.reported_calls = 0
        self.pending_escalation: Optional[str] = None


class LiveRecorder:
    def __init__(self, trace_dir: str, agent_label: str = "external agent (v1 API)"):
        self.trace_dir = trace_dir
        self.agent_label = agent_label
        self._runs: Dict[str, _Run] = {}
        self._lock = threading.Lock()

    # ---------------------------------------------------------------- decide
    def decide(self, request: dict) -> dict:
        scratch = Tracer()
        response = decide(request, tracer=scratch)
        try:
            with self._lock:
                self._record(request, response, scratch.events)
        except Exception:  # a broken trace must never change or fail a decision
            pass
        return response

    # ---------------------------------------------------------------- record
    def _run_for(self, request: dict) -> _Run:
        run_id = str(request.get("run_id") or "run")
        step = int(request.get("step_id") or 0)
        run = self._runs.get(run_id)
        if run is not None and step > 1:
            return run
        if run is not None:
            # The same run id starting again from the top: a fresh recording.
            run.tracer.close()
        name = SAFE_NAME.sub("_", run_id)[:120] or "run"
        path = os.path.join(self.trace_dir, f"{name}.jsonl")
        if os.path.exists(path):
            # The harness reuses a run id across passes (static, then adaptive).
            # Keep the earlier recording instead of silently overwriting it.
            n = 1
            while os.path.exists(os.path.join(self.trace_dir, f"{name}.prev{n}.jsonl")):
                n += 1
            os.replace(path, os.path.join(self.trace_dir, f"{name}.prev{n}.jsonl"))
        run = _Run(path)
        run.tracer.run_id = run_id
        self._runs[run_id] = run
        policy = request.get("policy_context") or {}
        run.tracer.emit(
            "run_start",
            scenario=run_id, title=run_id, domain=str(policy.get("policy_id") or "").split("_")[0],
            description="Recorded live from the v1 defense API.",
            policy_profile=str(policy.get("policy_id") or ""),
            defense="sentinel-v1", agent=self.agent_label, approver="harness",
            attack={}, allowed_tools=list(policy.get("allowed_tools") or []),
        )
        return run

    def _record(self, request: dict, response: dict, events: List[dict]) -> None:
        run = self._run_for(request)
        tracer = run.tracer
        history = request.get("history_digest") or {}
        step = int(request.get("step_id") or 0)

        self._report_previous(run, history)

        # The adapter rebuilds the ledger on every request, so the same content is
        # re-observed under a fresh id each time. Key observations by what they
        # are, give each a stable id for the recording, and translate the ids the
        # decision refers to.
        stable: Dict[str, str] = {}
        for event in events:
            fields = {k: v for k, v in event.items() if k not in ("seq", "t_ms", "run_id", "kind")}
            kind = event["kind"]
            if kind == "mandate_sealed":
                seal = fields["mandate"].get("seal")
                if seal == run.seal:
                    continue
                run.seal = seal
                run.turn = int(history.get("turn_index") or 0)
                fields["turn"] = run.turn
                tracer.emit("turn_start", turn=run.turn, goal=fields["mandate"].get("goal", ""))
                tracer.emit(kind, **fields)
            elif kind == "observation":
                key = (fields.get("source_ref"), fields.get("trust"), fields.get("chars"),
                       fields.get("excerpt"))
                if key in run.observations:
                    stable[fields["obs_id"]] = run.observations[key]
                    continue
                run.observations[key] = stable[fields["obs_id"]] = f"obs-{len(run.observations) + 1}"
                fields["obs_id"] = stable[fields["obs_id"]]
                fields["step"] = step
                tracer.emit(kind, **fields)
            elif kind == "decision":
                candidate = request.get("candidate_action") or {}
                target = candidate.get("confirmation_for") or candidate
                tracer.emit(
                    "agent_intent", step=step, turn=max(run.turn, 0),
                    tool=fields.get("candidate", {}).get("tool") or target.get("tool") or target.get("type"),
                    args=fields.get("candidate", {}).get("args") or target.get("arguments") or {},
                    # Ground truth about who authored a step belongs to the harness;
                    # a live recording does not have it and must not pretend to.
                    harness_label="unknown",
                    requested_as=candidate.get("type"),
                )
                fields = json.loads(OBS_ID.sub(lambda m: stable.get(m.group(), m.group()),
                                               json.dumps(fields, default=str)))
                fields["turn"] = max(run.turn, 0)
                fields["api_decision"] = response.get("decision")
                tracer.emit(kind, **fields)
                if response.get("decision") == "block":
                    tracer.emit("blocked", step=step, turn=max(run.turn, 0),
                                tool=target.get("tool"), reason=response.get("explanation"))
                run.pending_escalation = (
                    action_digest(target) if response.get("decision") == "escalate" else None)

    def _report_previous(self, run: _Run, history: dict) -> None:
        """What the harness did after our last decision, as the digest reports it."""
        if run.pending_escalation is not None:
            approved = run.pending_escalation in (history.get("confirmations_granted") or [])
            run.tracer.emit("human_review", approved=approved, mode="harness simulated human")
            run.pending_escalation = None
        # The digest only carries the most recent calls, so track by step, not index.
        calls = [c for c in (history.get("tool_calls") or [])
                 if int(c.get("step_id") or 0) > run.reported_calls]
        for call in calls:
            if call.get("succeeded") is True:
                run.tracer.emit("effect", step=call.get("step_id"), tool=call.get("tool"),
                                effect=f"{call.get('tool')} executed")
            elif call.get("succeeded") is False and call.get("decision") in ("allow", "rewrite"):
                run.tracer.emit("tool_error", step=call.get("step_id"), tool=call.get("tool"),
                                error="the tool rejected the call")
        if calls:
            run.reported_calls = max(int(c.get("step_id") or 0) for c in calls)


# ------------------------------------------------------------------ outcome
def attach_outcome(trace_path: str, harness_artifact: str) -> bool:
    """Append the harness's verdict for this run to a recorded trace.

    Reads the organizers' JSONL event log for the same run. This happens after
    the run, in the observability layer; the defense never sees these events.
    """
    events = load(trace_path)
    if not events or any(e["kind"] == "verdict" for e in events):
        return False
    with open(harness_artifact, "r", encoding="utf-8") as fh:
        theirs = [json.loads(line) for line in fh if line.strip()]
    if not theirs or theirs[0].get("run_id") != events[0].get("run_id"):
        return False

    findings = [e for e in theirs if e.get("type") == "policy_violation"]
    final = next((e for e in reversed(theirs)
                  if e.get("type") in ("task_success", "task_failure")), None)
    utility_pass = bool(final and final["type"] == "task_success")
    security_pass = not findings
    counts = {"ALLOW": 0, "REWRITE": 0, "ESCALATE": 0, "BLOCK": 0}
    for e in events:
        if e["kind"] == "decision" and e.get("intervention") in counts:
            counts[e["intervention"]] += 1

    summary = (final or {}).get("payload", {})
    verdict = {
        "overall": "PASS" if utility_pass and security_pass else "FAIL",
        "utility_pass": utility_pass,
        "security_pass": security_pass,
        "over_refusal": False,
        "utility": [{"name": "harness task grader", "passed": utility_pass,
                     "detail": f"{summary.get('summary', '')} (termination: {summary.get('termination', '?')})"}],
        "security": [{"name": "harness policy finding", "passed": False,
                      "detail": json.dumps(f.get("payload", {}))[:300]} for f in findings]
                    or [{"name": "harness policy findings", "passed": True, "detail": "none recorded"}],
        "leaked_canaries": [],
        "interventions": counts,
        "notes": "Verdict taken from the organizers' event log for this run.",
        "duration_ms": events[-1].get("t_ms"),
    }
    tracer = Tracer()
    tracer.run_id = events[0].get("run_id", "")
    tracer.events = events
    record = tracer.emit("verdict", **verdict)
    with open(trace_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, default=str) + "\n")
    return True


def attach_outcomes(trace_dir: str, harness_artifacts: str) -> int:
    """Match every recorded trace to the harness artifact with the same run id."""
    by_run: Dict[str, str] = {}
    for root, dirs, files in os.walk(harness_artifacts):
        dirs.sort()   # group directories are timestamped, so the latest run of an id wins
        for name in sorted(files):
            if name.endswith(".jsonl"):
                by_run[name[:-6]] = os.path.join(root, name)   # later groups win: most recent
    attached = 0
    for name in sorted(os.listdir(trace_dir)):
        if name.endswith(".jsonl") and name[:-6] in by_run:
            attached += attach_outcome(os.path.join(trace_dir, name), by_run[name[:-6]])
    return attached


if __name__ == "__main__":
    # python -m observability.live attach <trace_dir> <harness_artifacts_dir>
    import sys

    if len(sys.argv) != 4 or sys.argv[1] != "attach":
        raise SystemExit("usage: python -m observability.live attach TRACE_DIR HARNESS_ARTIFACTS_DIR")
    print(f"verdicts attached: {attach_outcomes(sys.argv[2], sys.argv[3])}")
