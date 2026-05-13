import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone

import clickhouse_logger
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
app = FastAPI(title="Checkout Service — AI War Room Assistant Demo", version=DEPLOYMENT_VERSION)


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
def _log_checkout(
    *,
    status_code: int,
    error: str | None,
    request_id: str,
    client_ip: str,
    method: str,
    response_time_ms: int,
) -> dict:
    record = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}",
        "request_id": request_id,
        "client_ip": client_ip,
        "endpoint": "/checkout",
        "method": method,
        "status_code": status_code,
        "error": error,
        "deployment_version": DEPLOYMENT_VERSION,
        "response_time_ms": response_time_ms,
    }
    print(json.dumps(record), flush=True)
    return record


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.get("/health", summary="Liveness probe")
def health():
    return {"status": "ok"}


@app.get("/checkout", summary="Process a checkout")
def checkout(request: Request, background_tasks: BackgroundTasks):
    global _healthy
    request_id = str(uuid.uuid4())
    start = time.perf_counter()

    forwarded = request.headers.get("X-Forwarded-For", "")
    client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "")

    if _healthy:
        response_time_ms = int((time.perf_counter() - start) * 1000)
        record = _log_checkout(
            status_code=200, error=None, request_id=request_id,
            client_ip=client_ip, method="GET", response_time_ms=response_time_ms,
        )
        background_tasks.add_task(clickhouse_logger.insert, record)
        return JSONResponse(status_code=200, content={"checkout": "ok"})

    response_time_ms = int((time.perf_counter() - start) * 1000)
    record = _log_checkout(
        status_code=500, error="payment_gateway_timeout", request_id=request_id,
        client_ip=client_ip, method="GET", response_time_ms=response_time_ms,
    )
    background_tasks.add_task(clickhouse_logger.insert, record)
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
