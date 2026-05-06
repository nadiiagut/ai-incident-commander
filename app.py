import json
import os
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Response
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


# ── Structured logger ──────────────────────────────────────────────────────────
def _log_checkout(*, status: int, error: str | None, request_id: str) -> None:
    print(
        json.dumps(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "service": SERVICE_NAME,
                "endpoint": "/checkout",
                "status": status,
                "error": error,
                "deployment_version": DEPLOYMENT_VERSION,
                "request_id": request_id,
            }
        ),
        flush=True,
    )


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/health", summary="Liveness probe")
def health():
    return {"status": "ok"}


@app.get("/checkout", summary="Process a checkout")
def checkout():
    global _healthy
    request_id = str(uuid.uuid4())

    if _healthy:
        _log_checkout(status=200, error=None, request_id=request_id)
        return JSONResponse(status_code=200, content={"checkout": "ok"})

    _log_checkout(status=500, error="payment_gateway_timeout", request_id=request_id)
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
