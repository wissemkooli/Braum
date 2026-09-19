"""SENTINEL defense service — the v1 API in front of the provenance guard.

The decision logic lives in `sentinel/`, which has no web dependencies. This
module is only a transport: validate the request, hand a plain dictionary to
the adapter, validate the response.
"""

from __future__ import annotations

import logging
import os

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.models import DefenseDecision, DefenseRequest
from sentinel import __version__
from sentinel.api_adapter import decide as adapter_decide

log = logging.getLogger("sentinel.defense")

app = FastAPI(title="SENTINEL defense", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "defense": "sentinel", "version": __version__}


@app.post("/v1/decision", response_model=DefenseDecision)
def decision(request: DefenseRequest) -> DefenseDecision:
    try:
        return DefenseDecision(**adapter_decide(request.model_dump(mode="json")))
    except Exception:
        # A defense that crashes must not become a defense that permits. Any
        # unexpected failure escalates to a human instead of failing open.
        log.exception("decision failed for run=%s step=%s", request.run_id, request.step_id)
        return DefenseDecision(
            decision="escalate",
            risk_score=0.5,
            confidence=0.05,
            reason_codes=["DEFENSE_INTERNAL_ERROR"],
            explanation="The defense could not evaluate this action, so a human decides.",
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), log_level="warning")
