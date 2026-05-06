# AI Incident Commander — Checkout Service Demo

A minimal FastAPI service used to demonstrate AI-driven incident command workflows.  
Toggle the service between **healthy** and **broken** mode at runtime to trigger real alert conditions.

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness probe — always returns `{"status":"ok"}` |
| `GET` | `/checkout` | Simulated checkout — `200 ok` or `500 payment_gateway_timeout` |
| `POST` | `/toggle-failure` | Flip between healthy and broken mode |
| `GET` | `/metrics` | Prometheus metrics |

---

## Run Locally

```bash
# Install dependencies
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start the server
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

API docs available at **http://localhost:8000/docs**

---

## Run with Docker Compose (recommended)

Starts the checkout service **and** Prometheus together on a shared network.

```bash
docker compose up --build
```

| Service | URL |
|---------|-----|
| Checkout API | http://localhost:8000 |
| Swagger UI | http://localhost:8000/docs |
| Prometheus | http://localhost:9090 |

Prometheus scrapes `/metrics` from `demo-edge-service:8000` every **5 seconds**.  
To query the counter in Prometheus: `http_requests_total{endpoint="/checkout"}`

```bash
# Stop and remove containers
docker compose down
```

## Run with Docker (standalone)

```bash
# Build
docker build -t checkout-service .

# Run (default version)
docker run -p 8000:8000 checkout-service

# Run with a custom deployment version label (appears in logs)
docker run -p 8000:8000 -e DEPLOYMENT_VERSION=2.1.0 checkout-service
```

---

## Demo Walkthrough

### 1. Verify healthy state

```bash
curl http://localhost:8000/checkout
# → 200  {"checkout":"ok"}
```

### 2. Break the service

```bash
curl -X POST http://localhost:8000/toggle-failure
# → {"mode":"broken","healthy":false}
```

### 3. Trigger the incident

```bash
curl http://localhost:8000/checkout
# → 500  {"error":"payment_gateway_timeout"}
```

Structured JSON log line emitted on every `/checkout` call:

```json
{
  "timestamp": "2026-05-06T14:32:01.123456+00:00",
  "service": "checkout-service",
  "endpoint": "/checkout",
  "status": 500,
  "error": "payment_gateway_timeout",
  "deployment_version": "1.0.0",
  "request_id": "b3d2f1a0-4c8e-4f2b-9a1d-7e3c6b5d8f90"
}
```

### 4. Inspect Prometheus metrics

```bash
curl http://localhost:8000/metrics
```

Key metrics:

| Metric | Type | Labels |
|--------|------|--------|
| `http_requests_total` | Counter | `endpoint`, `status_code` |
| `http_request_duration_seconds` | Histogram | `endpoint` |

### 5. Restore healthy state

```bash
curl -X POST http://localhost:8000/toggle-failure
# → {"mode":"healthy","healthy":true}
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEPLOYMENT_VERSION` | `1.0.0` | Version string included in every structured log line |
