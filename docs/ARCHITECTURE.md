# Architecture

## The one rule

```
simulator/  →  may import  →  sentinel/
sentinel/   →  may NOT import anything from simulator/ or scenarios/
```

The defense is a library that could be lifted out of this repository and
wrapped around a different agent. It receives a goal, a stream of labelled
observations, and candidate actions; it returns decisions. It has no idea it is
being evaluated. `tests/test_no_oracle.py` enforces this mechanically — see
README § *Scenario-specific hard-coding*.

## Data flow for a single step

```
                 user goal (trusted)
                        │
              derive_mandate()  ← tool_model.yaml (operator's declaration)
                        │  hash + seal
                        ▼
  ┌──────────────── Sentinel.review(action) ─────────────────┐
  │                                                           │
  │  attribute each argument ──► ContextLedger  ◄── observe() │
  │          │                    (provenance)                │
  │          ▼                                                │
  │   mandate │ origin │ context │ flow │ history   (signals) │
  │          │                                                │
  │          ▼                                                │
  │   risk.score()  →  logit sum, family caps, confidence     │
  │          │                                                │
  │          ├─► hard rules ──► intervention floor            │
  │          │                                                │
  │          ▼                                                │
  │   policy.risk_intervention(risk, severity, confidence)    │
  │          │                                                │
  │          ▼                                                │
  │   rewrite candidates, each re-scored by this same path    │
  │          │                                                │
  │          ▼  least restrictive that clears                 │
  │      Decision(allow | rewrite | escalate | block)         │
  └───────────────────────────────┬───────────────────────────┘
                                  ▼
                            Tracer.emit("decision", …)  →  JSONL
                                  ▼
                     replay.py  /  dashboard (same file)
```

Note that rewrite candidates re-enter `_evaluate` unchanged — a rewritten
action is judged by exactly the same machinery as the original, so a rewrite
can never be accepted on weaker grounds than an allow.

## Module responsibilities

| module | owns | deliberately does not |
|---|---|---|
| `trust.py` | the two lattices and their pessimistic joins | decide anything |
| `normalize.py` | bounded decoded views, canonical form, shingles | interpret meaning |
| `tool_model.yaml` | severity, argument roles, sinks, lifecycle, intent vocabulary, effect rules | mention any scenario |
| `capability.py` | loading that model; failing closed on unknown tools | know what exists at runtime |
| `context.py` | the provenance ledger; answering "who wrote this value?" | judge whether that is bad |
| `mandate.py` | reading the user's goal; sealing authority | read anything else |
| `signals.py` | producing `Evidence`, grouped into five families | weigh or decide |
| `risk.py` | log-odds aggregation, family caps, confidence | know about severity |
| `policy.py` | tolerances, block thresholds, hard rules, profiles | look at content |
| `rewrite.py` | proposing weaker actions | decide if they are good enough |
| `guard.py` | orchestration; the only place a decision is made | contain detection logic |
| `trace.py` | the event log | format anything for a human |

## Where to change things

| you want to… | edit |
|---|---|
| add a tool | `sentinel/tool_model.yaml` (+ an implementation in `simulator/tools.py`) |
| change how strict a domain is | `PROFILES` in `sentinel/policy.py` |
| decide irreversible actions need no human | `confirm_irreversible` in the profile |
| add a detection signal | a function in `sentinel/signals.py` + a weight in `risk.py` |
| add a rewrite strategy | `sentinel/rewrite.py`, then add it to `candidates()` |
| add a scenario | a YAML file under `scenarios/`; nothing else changes |
| add a baseline to compare against | `simulator/baselines.py` |

## Extension points

**A real model.** `simulator/agent.py` is a drop-in: anything that produces
`CandidateAction` objects and consumes tool results works. The guard's
interface is `begin_turn` / `observe` / `review` / `note_effect`.

**A different environment.** The guard needs only `(source_ref, text, trust,
sensitivity)` per observation. Point `observe()` at a real tool bus and the
defense works unchanged.

**Learned weights.** `risk.WEIGHTS` is a flat dict of log-odds priors. Fitting
them needs a corpus larger than nine scenarios — see TECHNICAL_REPORT § 4.6 for
why we did not.
