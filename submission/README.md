# SENTINEL defense — submission package

The organizers' v1 defense API in front of the provenance guard in
[`../sentinel/`](../sentinel). The decision logic has no web dependencies;
this directory is transport, container and manifest only.

```
app/main.py      FastAPI service: GET /healthz, POST /v1/decision
app/models.py    v1 schemas — lenient requests, strict responses
Dockerfile       python:3.12-slim, non-root (uid 10001), healthcheck
sentinel-submission.yaml   manifest: no external models, no datasets
```

## Run it locally

```bash
# from the repository root
pip install -r submission/requirements.txt
cd submission
PYTHONPATH=..:. uvicorn app.main:app --port 8099
curl -s localhost:8099/healthz
```

## Build the image

The build context is the **repository root**, because the image needs the
defense package as well as this directory:

```bash
docker build -f submission/Dockerfile -t sentinel-defense .
docker run --rm -p 8080:8080 sentinel-defense
```

## Validate and evaluate

```bash
# in a clone of the starter kit
uv run python scripts/validate_submission.py /path/to/this/repo/submission
uv run sentinel eval public --defense-url http://127.0.0.1:8099
```

Results and the defects this integration uncovered:
[`../docs/OFFICIAL_HARNESS.md`](../docs/OFFICIAL_HARNESS.md).

## Failure behaviour

If the guard raises for any reason, the service returns `escalate` with
confidence 0.05 and the code `DEFENSE_INTERNAL_ERROR`. A defense that crashes
must not become a defense that permits.
