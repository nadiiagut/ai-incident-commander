import json
import logging
import os
import time
import urllib.request
import uuid
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

# ── Configuration ──────────────────────────────────────────────────────────────
DEPLOYMENT_VERSION = os.getenv("DEPLOYMENT_VERSION", "1.0.0")
SERVICE_NAME = "checkout-service"
HYDROLIX_INGEST_URL: str = os.getenv("HYDROLIX_INGEST_URL", "")
HYDROLIX_TOKEN: str = os.getenv("HYDROLIX_TOKEN", "")

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
_log = logging.getLogger(SERVICE_NAME)

# ── Prometheus metrics ─────────────────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["endpoint", "status_code"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["endpoint"],
)

# ── Application state ──────────────────────────────────────────────────────────
_healthy = True

# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="Checkout Service — AI Incident Commander Demo", version=DEPLOYMENT_VERSION)


# ── Middleware: track all requests in Prometheus ───────────────────────────────
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    if request.url.path == "/metrics":
        return await call_next(request)
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start
    REQUEST_COUNT.labels(
        endpoint=request.url.path,
        status_code=str(response.status_code),
    ).inc()
    REQUEST_LATENCY.labels(endpoint=request.url.path).observe(duration)
    return response


# ── Hydrolix log shipper ───────────────────────────────────────────────────────
def _ship_to_hydrolix(record: dict) -> None:
    """POST a single log record to Hydrolix HTTP ingest. Never raises."""
    if not HYDROLIX_INGEST_URL or not HYDROLIX_TOKEN:
        return
    try:
        body = json.dumps(record).encode()
        req = urllib.request.Request(
            HYDROLIX_INGEST_URL,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {HYDROLIX_TOKEN}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status >= 400:
                _log.error(
                    "Hydrolix ingest returned HTTP %s for request_id=%s",
                    resp.status,
                    record.get("request_id"),
                )
    except Exception as exc:
        _log.error(
            "Hydrolix ingest failed: %s (request_id=%s)",
            exc,
            record.get("request_id"),
        )


# ── Structured logger ──────────────────────────────────────────────────────────
def _log_checkout(*, status: int, error: str | None, request_id: str) -> dict:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": SERVICE_NAME,
        "endpoint": "/checkout",
        "status": status,
        "error": error,
        "deployment_version": DEPLOYMENT_VERSION,
        "request_id": request_id,
    }
    print(json.dumps(record), flush=True)
    return record


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/health", summary="Liveness probe")
def health():
    return {"status": "ok"}


@app.get("/checkout", summary="Process a checkout")
def checkout(background_tasks: BackgroundTasks):
    global _healthy
    request_id = str(uuid.uuid4())

    if _healthy:
        record = _log_checkout(status=200, error=None, request_id=request_id)
        background_tasks.add_task(_ship_to_hydrolix, record)
        return JSONResponse(status_code=200, content={"checkout": "ok"})

    record = _log_checkout(status=500, error="payment_gateway_timeout", request_id=request_id)
    background_tasks.add_task(_ship_to_hydrolix, record)
    return JSONResponse(
        status_code=500,
        content={"error": "payment_gateway_timeout"},
    )


@app.post("/toggle-failure", summary="Toggle between healthy and broken mode")
def toggle_failure():
    global _healthy
    _healthy = not _healthy
    mode = "healthy" if _healthy else "broken"
    return {"mode": mode, "healthy": _healthy}


@app.get("/metrics", summary="Prometheus metrics", include_in_schema=False)
def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
