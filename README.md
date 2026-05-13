# AI War Room Assistant — Checkout Service Demo

A minimal FastAPI service used to demonstrate AI-driven war room workflows.  
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

> **Before first run** — create your `.env` from the example and fill in your keys:
> ```bash
> cp .env.example .env
> # Set OPENAI_API_KEY, IPINFO_TOKEN, CLICKHOUSE_USERNAME, and CLICKHOUSE_PASSWORD in .env
> ```

```bash
docker compose up --build
```

| Service | URL | Credentials |
|---------|-----|-------------|
| Checkout API | http://localhost:8000 | — |
| Swagger UI | http://localhost:8000/docs | — |
| AI Analyzer | http://localhost:8080/docs | — |
| Prometheus | http://localhost:9090 | — |
| Grafana | http://localhost:3000 | admin / admin |
| ClickHouse HTTP | http://localhost:8123 | — |
| Locust UI | http://localhost:8089 | — (load-test profile only) |

Prometheus scrapes `/metrics` from `demo-edge-service:8000` every **5 seconds**.  
Grafana opens at **http://localhost:3000** (admin / admin) with the **AI War Room Assistant — Checkout Service** dashboard pre-loaded.

Dashboard panels:

| Panel | Query |
|-------|-------|
| Request Rate | `rate(http_requests_total{endpoint="/checkout"}[1m])` |
| 500 Error Rate | `rate(http_requests_total{endpoint="/checkout",status_code="500"}[1m])` |
| p95 Latency | `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket{endpoint="/checkout"}[1m]))` |

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

## Creating an Alert Rule for 500 Errors

From Grafana UI after `docker compose up --build`:

1. Open **http://localhost:3000** → log in as `admin / admin`.
2. Navigate to **Alerting → Alert rules → New alert rule**.
3. Set **Rule name**: `checkout-500-error-rate`.
4. Under **Define query and alert condition**, paste the expression:
   ```
   rate(http_requests_total{endpoint="/checkout",status_code="500"}[1m])
   ```
5. Set **Threshold** condition: `IS ABOVE 0` (fires on any 500 error).
6. Under **Set evaluation behaviour**, create or select a folder and evaluation group with **Evaluate every `10s`**, **Pending period `0s`** (fires immediately).
7. Under **Configure labels and notifications**, add a label such as `severity=critical`.
8. Click **Save rule and exit**.

To trigger the alert: run `curl -X POST http://localhost:8000/toggle-failure`, then call `/checkout` a few times. The alert will move from `Normal → Firing` within one evaluation cycle.

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

## Synthetic Traffic Generator (Locust)

Locust drives realistic GET `/checkout` traffic with a fixed pool of public demo IPs sent via `X-Forwarded-For`.  
This ensures ClickHouse logs carry geographic diversity so `/analyze-incident` and `/monitor-incident` produce meaningful IPinfo breakdowns.

### IP pool coverage

| Region | IPs |
|---|---|
| North America | Google, Cloudflare, Quad9, OpenDNS |
| Europe | Yandex (RU), DNS.WATCH (DE), CleanBrowsing (GB), Mullvad (DE) |
| Asia-Pacific | KT (KR), NordVPN (SG), OVH (AU) |
| Other | TENET (ZA), Embratel (BR) |

### Traffic modes

| Class | Wait time | Rate | Use case |
|---|---|---|---|
| `NormalUser` | 0.8 – 1.5 s | ~1 req/s/user | Background baseline load |
| `IncidentUser` | 0.05 – 0.15 s | ~10 req/s/user | Fill ClickHouse fast during incident |
| `DemoShape` | automatic | cycles | Full automated demo progression |

### Run locally

```bash
pip install locust

# Normal background traffic — web UI at http://localhost:8089
locust -f locust/locustfile.py NormalUser --host http://localhost:8000

# Incident simulation (run after toggle-failure to generate 500s fast)
locust -f locust/locustfile.py IncidentUser --host http://localhost:8000

# Headless normal load (5 users, no browser needed)
locust -f locust/locustfile.py NormalUser \
  --host http://localhost:8000 \
  --headless --users 5 --spawn-rate 2

# Headless incident simulation (20 users)
locust -f locust/locustfile.py IncidentUser \
  --host http://localhost:8000 \
  --headless --users 20 --spawn-rate 10

# Automated demo shape: Normal (2 min) → Incident (3 min) → Recovery (2 min)
TRAFFIC_MODE=demo locust -f locust/locustfile.py \
  --host http://localhost:8000 \
  --headless --users 30 --spawn-rate 10
```

### Run with Docker Compose

The `locust` service uses the `load-test` profile so it never starts with a plain `docker compose up`.

```bash
# Web UI at http://localhost:8089 — configure users interactively
docker compose --profile load-test up locust

# Headless normal traffic
docker compose --profile load-test run --rm \
  locust locust -f /mnt/locust/locustfile.py NormalUser \
  --host http://demo-edge-service:8000 \
  --headless --users 5 --spawn-rate 2

# Automated demo shape (Normal → Incident → Recovery)
TRAFFIC_MODE=demo docker compose --profile load-test up locust
```

### Typical demo flow

```
1. docker compose up --build          # start all services
2. locust NormalUser (5 users)        # baseline: ClickHouse fills with 200s
3. curl -X POST localhost:8000/toggle-failure   # break the service
4. locust IncidentUser (20 users)     # flood ClickHouse with 500s
5. POST /analyze-incident             # LLM sees real evidence + IPinfo geo
6. POST /monitor-incident             # incident_status = still_failing
7. curl -X POST localhost:8000/toggle-failure   # restore healthy mode
8. wait 5 min, POST /monitor-incident # incident_status = recovered
```

---

## AI Incident Analyzer

The analyzer receives a normalized alert from n8n, queries ClickHouse for recent `/checkout` failures, enriches client IPs via IPinfo, and returns a structured Jira Bug report.

### Trigger an analysis manually

```bash
curl -s -X POST http://localhost:8080/analyze-incident \
  -H "Content-Type: application/json" \
  -d '{
    "alert_name": "checkout-500-error-rate",
    "service": "checkout-api",
    "severity": "critical",
    "status": "firing",
    "starts_at": "2026-05-10T09:30:00Z",
    "dashboard_url": "http://localhost:3000/d/incident-commander",
    "demo_mode": false
  }' | jq .
```

Use `"demo_mode": true` to get the hardcoded fallback response without calling OpenAI or ClickHouse.

### Monitor an existing incident (follow-up check)

**Still failing** — run this while the service is broken:

```bash
curl -s -X POST http://localhost:8080/monitor-incident \
  -H "Content-Type: application/json" \
  -d '{
    "service": "checkout-api",
    "endpoint": "/checkout",
    "incident_started_at": "2026-05-10T09:30:00Z",
    "jira_issue_key": "INC-42",
    "alert_name": "checkout-500-error-rate"
  }' | jq '{incident_status, status_summary, jira_comment}'
```

Expected when failures are still occurring in the last 5 min:
```json
{
  "incident_status": "still_failing",
  "status_summary": "Incident INC-42 is still active: N failures in the last 5 minutes ...",
  "jira_comment": "*[AI War Room Assistant — INC-42]*\n\n*Status:* Incident remains active ..."
}
```

**Recovered** — run this after toggling the service back to healthy and waiting 5 minutes:

```bash
curl -X POST http://localhost:8000/toggle-failure   # restore healthy mode
# wait 5 minutes, then:
curl -s -X POST http://localhost:8080/monitor-incident \
  -H "Content-Type: application/json" \
  -d '{
    "service": "checkout-api",
    "endpoint": "/checkout",
    "incident_started_at": "2026-05-10T09:30:00Z",
    "jira_issue_key": "INC-42"
  }' | jq '{incident_status, status_summary}'
```

Expected:
```json
{
  "incident_status": "recovered",
  "status_summary": "Incident INC-42 appears recovered: no /checkout 5xx responses in the last 5 minutes ..."
}
```

### Response fields — `/analyze-incident`

| Field | Description |
|-------|-------------|
| `incident_started_at` | Timestamp from first ClickHouse error row, or alert `starts_at` |
| `incident_summary` | 2–3 sentence summary |
| `probable_root_cause` | Root cause from log evidence |
| `customer_impact` | Customer-facing impact description |
| `immediate_actions` | Ordered remediation steps |
| `jira_incident_title` | Ready-to-use Jira Bug title |
| `jira_incident_description` | Full Jira wiki markup including log evidence and geographic impact |

### Response fields — `/monitor-incident`

| Field | Description |
|-------|-------------|
| `jira_issue_key` | Echoed from request |
| `incident_status` | `still_failing` · `recovered` · `monitoring_failed` |
| `status_summary` | One-sentence plain-text status for display |
| `jira_comment` | Ready-to-post Jira comment in wiki markup |
| `evidence.total_failed_requests_since_incident_start` | Count of 5xx rows from `incident_started_at` until now |
| `evidence.failed_requests_last_5m` | Count of 5xx rows in the last 5 minutes |
| `evidence.first_seen` | Earliest 5xx timestamp since incident start |
| `evidence.latest_failed_request` | Most recent 5xx timestamp since incident start |
| `evidence.dominant_error` | Most frequent error string |
| `evidence.top_country` | Top affected country from IPinfo (empty if unavailable) |
| `evidence.top_asn` | Top affected ASN from IPinfo (empty if unavailable) |

### Evidence pipeline

```
ClickHouse (last 10 min, /checkout, status>=500)
  └─ 0 rows     → "no evidence found" note injected into prompt
  └─ rows found → enrich unique client_ips via IPinfo Lite
                    → failures_by_country, failures_by_asn, impact_scope
  └─ unavailable → static mock evidence (demo still works)
```

---

## ClickHouse — Log Analytics Backend

ClickHouse stores structured log events from `demo-edge-service` for evidence-backed incident analysis.  
The `incident_demo` database and `checkout_logs` table are created automatically on first start via `clickhouse/init/01_init.sql`.

### Verify ClickHouse is alive

```bash
curl http://localhost:8123/ping
# → Ok.
```

### Show the checkout_logs table schema

```bash
curl "http://localhost:8123/?query=DESCRIBE+incident_demo.checkout_logs"
```

### Send a checkout request with a custom client IP

```bash
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8000/checkout
```

The service reads the first IP from `X-Forwarded-For` when present, otherwise uses the raw TCP remote address.

### Confirm the row was written to ClickHouse

```bash
curl "http://localhost:8123/?query=SELECT+request_id,client_ip,status_code,error,response_time_ms+FROM+incident_demo.checkout_logs+ORDER+BY+timestamp+DESC+LIMIT+1+FORMAT+JSONEachRow"
```

Expected output:
```json
{"request_id":"...","client_ip":"1.2.3.4","status_code":200,"error":null,"response_time_ms":0}
```

### Query the latest logs

```bash
curl "http://localhost:8123/?query=SELECT+*+FROM+incident_demo.checkout_logs+ORDER+BY+timestamp+DESC+LIMIT+10+FORMAT+JSONEachRow"
```

### Query recent errors only

```bash
curl "http://localhost:8123/?query=SELECT+*+FROM+incident_demo.checkout_logs+WHERE+status_code>=500+ORDER+BY+timestamp+DESC+LIMIT+20+FORMAT+JSONEachRow"
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `DEPLOYMENT_VERSION` | `1.0.0` | Version string included in every structured log line |
| `OPENAI_API_KEY` | _(empty)_ | OpenAI key — omit to use hardcoded fallback analysis |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model used by the analyzer |
| `CLICKHOUSE_URL` | `http://clickhouse:8123` | ClickHouse HTTP endpoint |
| `CLICKHOUSE_DATABASE` | `incident_demo` | Target database |
| `CLICKHOUSE_TABLE` | `checkout_logs` | Target table |
| `CLICKHOUSE_USERNAME` | _(required)_ | ClickHouse user — must match `CLICKHOUSE_USER` set on the server |
| `CLICKHOUSE_PASSWORD` | _(required)_ | ClickHouse password for the above user |
| `IPINFO_TOKEN` | _(empty)_ | IPinfo API token — enables geographic IP enrichment |

---

## Run in Kubernetes

Manifests are in `k8s/`. They deploy the checkout-api into the `ai-rca-demo` namespace using a locally built image.

### 1. Build the Docker image

```bash
docker build -t checkout-api:local .
```

> If you use **minikube**, load the image into the cluster so it is available without a registry:
> ```bash
> minikube image load checkout-api:local
> ```

### 2. Create the namespace

```bash
kubectl apply -f k8s/namespace.yaml
```

### 3. Apply all manifests

```bash
kubectl apply -f k8s/
```

This creates the ConfigMap, Deployment, and Service in the `ai-rca-demo` namespace.

### 4. Check pods

```bash
kubectl get pods -n ai-rca-demo
```

Expected output once ready:
```
NAME                            READY   STATUS    RESTARTS   AGE
checkout-api-<hash>             1/1     Running   0          30s
```

### 5. Port-forward the service

```bash
kubectl port-forward svc/checkout-api 8000:8000 -n ai-rca-demo
```

### 6. Test /health

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

### 7. Test /metrics

```bash
curl http://localhost:8000/metrics
```

### Tear down

```bash
kubectl delete -f k8s/
```
