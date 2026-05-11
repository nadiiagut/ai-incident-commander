import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import clickhouse_client
import ipinfo_client
from fastapi import FastAPI
from openai import OpenAI
from pydantic import BaseModel, Field

# ── Configuration ──────────────────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
CLICKHOUSE_URL: str = os.getenv("CLICKHOUSE_URL", "")
CLICKHOUSE_DATABASE: str = os.getenv("CLICKHOUSE_DATABASE", "incident_demo")
CLICKHOUSE_TABLE: str = os.getenv("CLICKHOUSE_TABLE", "checkout_logs")
CLICKHOUSE_USERNAME: str = os.getenv("CLICKHOUSE_USERNAME", "")
CLICKHOUSE_PASSWORD: str = os.getenv("CLICKHOUSE_PASSWORD", "")
IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ai-incident-analyzer")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    log.info(
        "Config | CLICKHOUSE_URL=%r  database=%r  table=%r  username=%r  password_set=%s",
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE,
        CLICKHOUSE_USERNAME, bool(CLICKHOUSE_PASSWORD),
    )
    log.info(
        "Config | OPENAI_MODEL=%r  openai_key_set=%s  ipinfo_token_set=%s",
        OPENAI_MODEL, bool(OPENAI_API_KEY), bool(IPINFO_TOKEN),
    )
    yield

# ── Pydantic models ────────────────────────────────────────────────────────────

class AlertPayload(BaseModel):
    """Normalised alert fields forwarded by the n8n workflow."""

    service: str = Field(default="checkout-api", description="Service name")
    alert_name: str = Field(..., description="Alert name from Grafana")
    severity: str = Field(default="unknown", description="Alert severity (critical/warning/…)")
    status: str = Field(default="firing", description="Alert status (firing/resolved)")
    starts_at: str = Field(default="", description="Alert start time — ISO 8601")
    dashboard_url: str = Field(default="", description="Grafana dashboard URL")
    demo_mode: bool = Field(default=False, description="Return hardcoded demo response (no LLM)")


class IncidentAnalysis(BaseModel):
    """Structured analysis returned to n8n for Jira Bug creation."""

    incident_started_at: str = Field(..., description="When the incident started (ISO timestamp or 'unknown')")
    incident_summary: str = Field(..., description="2–3 sentence incident summary")
    probable_root_cause: str = Field(..., description="Most likely root cause from log evidence")
    customer_impact: str = Field(..., description="How end-customers are affected right now")
    immediate_actions: list[str] = Field(..., description="Ordered list of immediate remediation steps")
    jira_incident_title: str = Field(..., description="Concise Jira Bug title (≤80 chars)")
    jira_incident_description: str = Field(..., description="Detailed Jira Bug description in Jira wiki markup")


# ── Monitor models ────────────────────────────────────────────────────────────

class MonitorRequest(BaseModel):
    """Request body for POST /monitor-incident."""

    service: str = Field(default="checkout-api", description="Service name")
    endpoint: str = Field(default="/checkout", description="Endpoint to monitor")
    incident_started_at: str = Field(..., description="ISO 8601 incident start timestamp")
    jira_issue_key: str = Field(..., description="Jira issue key, e.g. INC-42")
    alert_name: str = Field(default="", description="Original Grafana alert name")


class MonitorEvidence(BaseModel):
    """Raw metrics collected during the monitoring check."""

    total_failed_requests_since_incident_start: int
    failed_requests_last_5m: int
    first_seen: str
    latest_failed_request: str
    dominant_error: str
    top_country: str
    top_asn: str


class MonitorResponse(BaseModel):
    """Response returned by POST /monitor-incident."""

    jira_issue_key: str
    incident_status: str = Field(..., description="still_failing | recovered | monitoring_failed")
    status_summary: str
    jira_comment: str
    evidence: MonitorEvidence


# ── Log evidence (ClickHouse + IPinfo) ─────────────────────────────────────────────

def _fetch_log_evidence(service: str) -> dict:
    """
    Try ClickHouse first; fall back to static mock when unavailable.
    Adds IPinfo enrichment for unique client IPs when ClickHouse returns rows.
    """
    if not CLICKHOUSE_URL:
        log.warning("CLICKHOUSE_URL is empty — skipping live query, using mock evidence")
        return _mock_evidence(service)

    log.info(
        "Fetching log evidence | url=%s db=%s table=%s username=%r",
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE, CLICKHOUSE_USERNAME,
    )
    evidence = clickhouse_client.fetch_evidence(
        query_url=CLICKHOUSE_URL,
        database=CLICKHOUSE_DATABASE,
        table=CLICKHOUSE_TABLE,
        username=CLICKHOUSE_USERNAME,
        password=CLICKHOUSE_PASSWORD,
    )

    if evidence is None:
        log.warning(
            "ClickHouse query failed — using mock evidence "
            "(check logs above for HTTP status / error body)"
        )
        return _mock_evidence(service)

    if evidence.get("no_data"):
        log.info("ClickHouse: query OK but 0 rows match (last 10 min, /checkout, status>=500)")
        evidence["enrichment"] = {"available": False, "reason": "No matching log evidence found in ClickHouse"}
        return evidence

    unique_ips: list[str] = evidence.get("unique_ips", [])[:20]
    if unique_ips:
        raw = ipinfo_client.enrich_ips(unique_ips, IPINFO_TOKEN)
        if raw:
            evidence["enrichment"] = ipinfo_client.summarize_enrichment(evidence["ip_counts"], raw)
            log.info("IPinfo enrichment: %d IPs, scope=%s",
                     len(raw), evidence["enrichment"].get("impact_scope"))
        else:
            log.info("IPinfo enrichment returned no results")
            evidence["enrichment"] = {"available": False, "reason": "IPinfo enrichment returned no results"}
    else:
        evidence["enrichment"] = {"available": False, "reason": "No client IPs in log data"}

    return evidence


def _mock_evidence(service: str) -> dict:
    """Static mocked evidence used when ClickHouse is unavailable."""
    return {
        "source": "mock",
        "service": service,
        "failed_request_count": 3,
        "first_seen": "",
        "latest_seen": "",
        "dominant_error": "payment_gateway_timeout",
        "deployment_versions": ["v1.2.8"],
        "enrichment": {"available": False, "reason": "ClickHouse unavailable"},
        "recent_sample": [
            {"timestamp": "2026-05-06 14:00:12.000", "status_code": 500,
             "error": "payment_gateway_timeout", "deployment_version": "v1.2.8"},
            {"timestamp": "2026-05-06 14:00:18.000", "status_code": 500,
             "error": "payment_gateway_timeout", "deployment_version": "v1.2.8"},
            {"timestamp": "2026-05-06 14:00:24.000", "status_code": 500,
             "error": "payment_gateway_timeout", "deployment_version": "v1.2.8"},
        ],
    }


# ── Prompt construction ────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are an expert AI incident commander for software engineering teams. "
    "Analyse production alerts and log evidence to produce structured incident reports. "
    "Always respond with a single valid JSON object — no markdown fences, no extra text."
)


def _build_user_message(alert: AlertPayload, evidence: dict) -> str:
    alert_block = json.dumps(
        {
            "alert_name": alert.alert_name,
            "service": alert.service,
            "severity": alert.severity,
            "status": alert.status,
            "starts_at": alert.starts_at,
            "dashboard_url": alert.dashboard_url,
        },
        indent=2,
    )
    evidence_block = json.dumps(evidence, indent=2)

    no_data_note = ""
    if evidence.get("no_data"):
        no_data_note = (
            "\nIMPORTANT: No matching log evidence was found in ClickHouse for the last 10 minutes. "
            "Do NOT fabricate log evidence. Clearly state in your analysis that no log evidence is available "
            "and base your assessment on the alert metadata only.\n"
        )

    return (
        "Production alert received. Analyse the following and return ONLY a JSON object.\n\n"
        f"## Alert\n{alert_block}\n\n"
        f"{no_data_note}"
        f"## Log Evidence\n{evidence_block}\n\n"
        "## Required JSON Response Shape\n"
        "{\n"
        '  "incident_started_at": "ISO timestamp from evidence.first_seen, or alert.starts_at, or unknown",\n'
        '  "incident_summary": "2-3 sentence summary",\n'
        '  "probable_root_cause": "Root cause from evidence",\n'
        '  "customer_impact": "How end-customers are affected",\n'
        '  "immediate_actions": ["step 1", "step 2", "step 3"],\n'
        '  "jira_incident_title": "Concise Jira Bug title (max 80 chars)",\n'
        '  "jira_incident_description": "Jira wiki markup. Must include sections: Incident Summary '
        '(alert metadata), Log Evidence (failed_request_count, first_seen, latest_seen, dominant_error, '
        'deployment_version), Geographic Impact (top countries and ASNs from enrichment, or N/A), '
        'Recent Log Sample (table of last 5 rows), Actions Taken (placeholder)"\n'
        "}\n\n"
        "Return ONLY the JSON object. No markdown fences, no extra text."
    )


# ── Jira description builder ──────────────────────────────────────────────────

def _build_jira_description(alert: AlertPayload, evidence: dict, started: str) -> str:
    """
    Build Jira wiki-markup description using real evidence when available,
    degrading gracefully when ClickHouse or IPinfo data is absent.
    """
    has_live = evidence.get("source") == "clickhouse" and not evidence.get("no_data")

    header = (
        "h2. Incident Summary\n\n"
        f"*Alert:* {alert.alert_name}\n"
        f"*Service:* {alert.service}\n"
        f"*Severity:* {alert.severity}\n"
        f"*Started:* {started}\n"
        f"*Dashboard:* {alert.dashboard_url or 'N/A'}\n\n"
    )

    if has_live:
        count = evidence.get("failed_request_count", 0)
        first = evidence.get("first_seen") or "N/A"
        latest = evidence.get("latest_seen") or "N/A"
        dominant = evidence.get("dominant_error") or "N/A"
        versions = ", ".join(evidence.get("deployment_versions", [])) or "N/A"

        ip_counts: dict = evidence.get("ip_counts", {})
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ip_lines = "\n".join(f"* {ip} ({cnt} req)" for ip, cnt in top_ips) or "* N/A"

        ev_section = (
            "h2. Log Evidence\n\n"
            "*Source:* ClickHouse (live)\n"
            f"*Failed Requests:* {count}\n"
            f"*First Seen:* {first}\n"
            f"*Latest Seen:* {latest}\n"
            f"*Dominant Error:* {dominant}\n"
            f"*Deployment Versions:* {versions}\n\n"
            "h3. Top Client IPs\n\n"
            f"{ip_lines}\n\n"
        )

        sample: list[dict] = evidence.get("recent_sample", [])
        if sample:
            bullets = ""
            for row in sample[:5]:
                ts = row.get("event_timestamp") or "N/A"
                ip = row.get("client_ip") or "N/A"
                ep = row.get("endpoint") or "N/A"
                sc = row.get("status_code", "N/A")
                err = str(row.get("error") or "N/A")[:60]
                ver = row.get("deployment_version") or "N/A"
                lat = row.get("response_time_ms", "N/A")
                bullets += f"* {ts} | {ip} | {ep} | {sc} | {err} | deployment={ver} | latency={lat}ms\n"
            ev_section += f"h3. Recent Failed Requests\n\n{bullets}\n"
    else:
        ev_section = (
            "h2. Log Evidence\n\n"
            "_Live ClickHouse evidence not available — see Grafana dashboard for current metrics._\n\n"
        )

    enrichment: dict = evidence.get("enrichment", {})
    if enrichment.get("available") is not False and enrichment:
        countries: dict = enrichment.get("failures_by_country", {})
        country_lines = "\n".join(
            f"* {c}: {n} req"
            for c, n in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
        ) or "* N/A"
        top_asn = enrichment.get("top_affected_asn") or "N/A"
        scope = enrichment.get("impact_scope") or "N/A"
        geo_section = (
            "h2. Geographic Impact\n\n"
            f"*Impact Scope:* {scope}\n"
            f"*Top Affected ASN:* {top_asn}\n\n"
            "h3. Failures by Country\n\n"
            f"{country_lines}\n\n"
        )
    elif has_live:
        geo_section = (
            "h2. Geographic Impact\n\n"
            "_IPinfo enrichment unavailable — raw client IP evidence is included above._\n\n"
        )
    else:
        geo_section = "h2. Geographic Impact\n\n_IPinfo enrichment not available._\n\n"

    actions = (
        "h2. Recommended Immediate Actions\n\n"
        "* Validate whether the issue started after the listed deployment version.\n"
        "* Check payment gateway connectivity and timeout configuration.\n"
        "* Roll back or disable the affected checkout path if failures continue.\n"
        "* Monitor checkout 5xx rate in Grafana after mitigation.\n"
        "* Keep this Jira Bug updated with automated follow-up evidence."
    )
    return header + ev_section + geo_section + actions


# ── Safe fallback ────────────────────────────────────────────────────────────────

def _fallback(
    alert: AlertPayload,
    incident_started_at: str = "",
    evidence: dict | None = None,
) -> IncidentAnalysis:
    """
    Deterministic response used when:
    - demo_mode is True
    - OPENAI_API_KEY is absent
    - The LLM call fails for any reason
    Always uses real evidence when available.
    """
    started = incident_started_at or alert.starts_at or "unknown"
    ev = evidence or {}
    has_live = ev.get("source") == "clickhouse" and not ev.get("no_data")

    if has_live:
        count = ev.get("failed_request_count", 0)
        dominant = ev.get("dominant_error") or "unknown"
        incident_summary = (
            f"Alert '{alert.alert_name}' is firing for service '{alert.service}' "
            f"with severity {alert.severity}. "
            f"{count} failed /checkout requests observed since {started}. "
            f"Dominant error: {dominant}."
        )
        probable_root_cause = (
            f"Live ClickHouse evidence shows {count} failed requests with dominant error '{dominant}'. "
            "Review recent deployments and downstream dependencies for the root cause."
        )
    else:
        incident_summary = (
            f"Alert '{alert.alert_name}' is firing for service '{alert.service}' "
            f"with severity {alert.severity}. "
            "HTTP 500 errors detected on the /checkout endpoint."
        )
        probable_root_cause = (
            "A recent deployment introduced a regression in the payment gateway client. "
            "All checkout requests are failing with payment_gateway_timeout."
        )

    return IncidentAnalysis(
        incident_started_at=started,
        incident_summary=incident_summary,
        probable_root_cause=probable_root_cause,
        customer_impact=(
            "Checkout attempts are failing. Customers cannot complete purchases. "
            "Revenue impact grows linearly until the incident is resolved."
        ),
        immediate_actions=[
            f"Rollback {alert.service} to the last known-good version immediately",
            "Verify payment gateway connectivity independently",
            "Page the on-call engineer and the release owner",
            "Open a war-room channel and post status to the customer status page",
            "Monitor error rate after rollback to confirm resolution",
        ],
        jira_incident_title=f"[INCIDENT] {alert.alert_name} — {alert.service} checkout failures",
        jira_incident_description=_build_jira_description(alert, ev, started),
    )


# ── OpenAI call ────────────────────────────────────────────────────────────────

def _call_openai(alert: AlertPayload, evidence: dict) -> IncidentAnalysis:
    log.info("Calling OpenAI model=%s for alert=%s", OPENAI_MODEL, alert.alert_name)
    client = OpenAI(api_key=OPENAI_API_KEY)
    completion = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_message(alert, evidence)},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
        timeout=25,
    )
    raw = completion.choices[0].message.content
    log.info("OpenAI response received (%d chars)", len(raw or ""))
    return IncidentAnalysis(**json.loads(raw))


# ── Monitor helpers ────────────────────────────────────────────────────────────

def _parse_ts(ts: str) -> str:
    """Normalise any ISO 8601-ish timestamp to 'YYYY-MM-DD HH:MM:SS.mmm' UTC."""
    normalised = ts.strip().replace("T", " ")
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalised)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _build_status_summary(status: str, ev: MonitorEvidence, req: MonitorRequest) -> str:
    if status == "still_failing":
        return (
            f"Incident {req.jira_issue_key} is still active: "
            f"{ev.failed_requests_last_5m} failures in the last 5 minutes "
            f"({ev.total_failed_requests_since_incident_start} total since incident start). "
            f"Dominant error: {ev.dominant_error or 'N/A'}."
        )
    if status == "recovered":
        return (
            f"Incident {req.jira_issue_key} appears recovered: "
            "no /checkout 5xx responses in the last 5 minutes. "
            f"Total failures since incident start: {ev.total_failed_requests_since_incident_start}. "
            "Continue monitoring before closing."
        )
    return f"Automated monitoring failed for incident {req.jira_issue_key}."


def _build_jira_comment(status: str, ev: MonitorEvidence, req: MonitorRequest) -> str:
    geo = ""
    if ev.top_country or ev.top_asn:
        geo = f"\n*Top Affected:* Country: {ev.top_country or 'N/A'}, ASN: {ev.top_asn or 'N/A'}"

    if status == "still_failing":
        return (
            f"*[AI Incident Monitor \u2014 {req.jira_issue_key}]*\n\n"
            "*Status:* Incident remains active\n\n"
            f"*Failed Requests (last 5 min):* {ev.failed_requests_last_5m}\n"
            f"*Total Since Incident Start:* {ev.total_failed_requests_since_incident_start}\n"
            f"*Dominant Error:* {ev.dominant_error or 'N/A'}\n"
            f"*Latest Failed Request:* {ev.latest_failed_request or 'N/A'}"
            f"{geo}\n\n"
            "_No automated Jira transition performed. Review and resolve manually._"
        )
    if status == "recovered":
        return (
            f"*[AI Incident Monitor \u2014 {req.jira_issue_key}]*\n\n"
            "*Status:* No new failures observed\n\n"
            f"No new {req.endpoint} 5xx responses were observed in the last 5 minutes.\n\n"
            f"*Latest Failed Request:* {ev.latest_failed_request or 'N/A'}\n"
            f"*Total Since Incident Start:* {ev.total_failed_requests_since_incident_start}\n\n"
            "The incident appears mitigated but should continue to be monitored before closure.\n\n"
            "_No automated Jira transition performed. Verify manually before closing._"
        )
    return (
        f"*[AI Incident Monitor \u2014 {req.jira_issue_key}]*\n\n"
        "The automated follow-up could not retrieve log evidence.\n\n"
        "_Manual verification of current service health is recommended._"
    )


def _monitor_failed(req: MonitorRequest, reason: str) -> MonitorResponse:
    log.warning("Monitor failed for %s: %s", req.jira_issue_key, reason)
    return MonitorResponse(
        jira_issue_key=req.jira_issue_key,
        incident_status="monitoring_failed",
        status_summary=f"Automated monitoring failed: {reason}",
        jira_comment=_build_jira_comment("monitoring_failed", MonitorEvidence(
            total_failed_requests_since_incident_start=0,
            failed_requests_last_5m=0,
            first_seen="",
            latest_failed_request="",
            dominant_error="",
            top_country="",
            top_asn="",
        ), req),
        evidence=MonitorEvidence(
            total_failed_requests_since_incident_start=0,
            failed_requests_last_5m=0,
            first_seen="",
            latest_failed_request="",
            dominant_error="",
            top_country="",
            top_asn="",
        ),
    )


# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Incident Analyzer",
    description="Analyses Grafana alerts with live ClickHouse evidence and IPinfo enrichment to produce Jira Bug reports.",
    version="2.0.0",
    lifespan=_lifespan,
)


@app.get("/health", summary="Liveness probe")
def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/analyze-incident",
    response_model=IncidentAnalysis,
    summary="Analyse a firing alert and return a structured Jira Bug report",
)
def analyze_incident(alert: AlertPayload) -> IncidentAnalysis:
    log.info("Received alert: %s | service=%s severity=%s demo_mode=%s",
             alert.alert_name, alert.service, alert.severity, alert.demo_mode)

    evidence = _fetch_log_evidence(alert.service)
    incident_started_at = evidence.get("first_seen") or alert.starts_at or "unknown"
    log.info(
        "Evidence source=%s  failed_count=%s  dominant_error=%r  first_seen=%r  incident_started_at=%r",
        evidence.get("source"),
        evidence.get("failed_request_count", "n/a"),
        evidence.get("dominant_error", "n/a"),
        evidence.get("first_seen"),
        incident_started_at,
    )

    if alert.demo_mode:
        log.info("demo_mode=True — using fallback with live evidence")
        return _fallback(alert, incident_started_at, evidence)

    if not OPENAI_API_KEY:
        log.warning("OPENAI_API_KEY not set — using fallback with live evidence")
        return _fallback(alert, incident_started_at, evidence)

    try:
        result = _call_openai(alert, evidence)
        log.info("Response generated by OpenAI for alert: %s", alert.alert_name)
        return result
    except Exception as exc:
        log.error("OpenAI call failed (%s) — using fallback with live evidence", exc)
        return _fallback(alert, incident_started_at, evidence)


@app.post(
    "/monitor-incident",
    response_model=MonitorResponse,
    summary="Follow-up monitoring check for an existing Jira incident",
)
def monitor_incident(req: MonitorRequest) -> MonitorResponse:
    log.info("Monitor: %s | endpoint=%s since=%s",
             req.jira_issue_key, req.endpoint, req.incident_started_at)

    if not CLICKHOUSE_URL:
        return _monitor_failed(req, "CLICKHOUSE_URL not configured")

    try:
        since_ts = _parse_ts(req.incident_started_at)
    except Exception as exc:
        return _monitor_failed(req, f"Invalid incident_started_at: {exc}")

    since_expr = f"toDateTime64('{since_ts}', 3, 'UTC')"

    full_ev = clickhouse_client.fetch_since(
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE, req.endpoint, since_expr,
        CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD,
    )
    if full_ev is None:
        return _monitor_failed(req, "ClickHouse query failed (full window)")

    recent_ev = clickhouse_client.fetch_since(
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE,
        req.endpoint, "now() - INTERVAL 5 MINUTE",
        CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD,
    )
    if recent_ev is None:
        return _monitor_failed(req, "ClickHouse query failed (5-minute window)")

    total_failed = 0 if full_ev.get("no_data") else full_ev["failed_request_count"]
    last_5m = 0 if recent_ev.get("no_data") else recent_ev["failed_request_count"]
    latest_ts = "" if full_ev.get("no_data") else full_ev.get("latest_seen", "")
    dominant_error = "" if full_ev.get("no_data") else full_ev.get("dominant_error", "")

    top_country = ""
    top_asn = ""
    if not full_ev.get("no_data") and full_ev.get("unique_ips"):
        raw = ipinfo_client.enrich_ips(full_ev["unique_ips"][:10], IPINFO_TOKEN)
        if raw:
            enrich_summary = ipinfo_client.summarize_enrichment(full_ev["ip_counts"], raw)
            top_country = next(iter(enrich_summary.get("failures_by_country", {})), "")
            top_asn = enrich_summary.get("top_affected_asn", "")

    status = "still_failing" if last_5m > 0 else "recovered"
    log.info("Monitor result: %s | last5m=%d total=%d", status, last_5m, total_failed)

    first_seen = "" if full_ev.get("no_data") else full_ev.get("first_seen", "")

    evidence = MonitorEvidence(
        total_failed_requests_since_incident_start=total_failed,
        failed_requests_last_5m=last_5m,
        first_seen=first_seen,
        latest_failed_request=latest_ts,
        dominant_error=dominant_error,
        top_country=top_country,
        top_asn=top_asn,
    )
    return MonitorResponse(
        jira_issue_key=req.jira_issue_key,
        incident_status=status,
        status_summary=_build_status_summary(status, evidence, req),
        jira_comment=_build_jira_comment(status, evidence, req),
        evidence=evidence,
    )
