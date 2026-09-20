# Build context is the repository root:  docker build -f submission/Dockerfile .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /srv

COPY submission/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# The defense core and the transport in front of it.
COPY sentinel/ ./sentinel/
# Optional live trace recorder (enabled with SENTINEL_TRACE_DIR).
COPY observability/ ./observability/
COPY submission/app/ ./app/

RUN useradd --create-home --uid 10001 sentinel && chown -R sentinel:sentinel /srv
USER sentinel

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "warning"]
