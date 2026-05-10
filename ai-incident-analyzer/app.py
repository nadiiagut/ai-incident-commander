import json
import logging
import os

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
IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("ai-incident-analyzer")

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


# ── Log evidence (ClickHouse + IPinfo) ─────────────────────────────────────────────

def _fetch_log_evidence(service: str) -> dict:
    """
    Try ClickHouse first; fall back to static mock when unavailable.
    Adds IPinfo enrichment for unique client IPs when ClickHouse returns rows.
    """
    evidence = clickhouse_client.fetch_evidence(
        query_url=CLICKHOUSE_URL,
        database=CLICKHOUSE_DATABASE,
        table=CLICKHOUSE_TABLE,
    )

    if evidence is None:
        log.info("ClickHouse unavailable — using mocked evidence")
        return _mock_evidence(service)

    if evidence.get("no_data"):
        log.info("No matching logs in ClickHouse (last 10 min, /checkout, status>=500)")
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


# ── Safe fallback ────────────────────────────────────────────────────────────────

def _fallback(alert: AlertPayload, incident_started_at: str = "") -> IncidentAnalysis:
    """
    Deterministic response used when:
    - demo_mode is True
    - OPENAI_API_KEY is absent
    - The LLM call fails for any reason
    """
    started = incident_started_at or alert.starts_at or "unknown"
    return IncidentAnalysis(
        incident_started_at=started,
        incident_summary=(
            f"Alert '{alert.alert_name}' is firing for service '{alert.service}' "
            f"with severity {alert.severity}. "
            "HTTP 500 errors detected on the /checkout endpoint."
        ),
        probable_root_cause=(
            "A recent deployment introduced a regression in the payment gateway client. "
            "All checkout requests are failing with payment_gateway_timeout."
        ),
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
        jira_incident_description=(
            "h2. Incident Summary\n\n"
            f"*Alert:* {alert.alert_name}\n"
            f"*Service:* {alert.service}\n"
            f"*Severity:* {alert.severity}\n"
            f"*Started:* {started}\n"
            f"*Dashboard:* {alert.dashboard_url or 'N/A'}\n\n"
            "h2. Log Evidence\n\n"
            "_Live ClickHouse evidence not available — see Grafana dashboard for current metrics._\n\n"
            "h2. Geographic Impact\n\n"
            "_IPinfo enrichment not available._\n\n"
            "h2. Actions Taken\n\n"
            "* _To be filled by on-call engineer_"
        ),
    )


# ── OpenAI call ────────────────────────────────────────────────────────────────

def _call_openai(alert: AlertPayload, evidence: dict) -> IncidentAnalysis:
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
    return IncidentAnalysis(**json.loads(raw))


# ── FastAPI app ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI Incident Analyzer",
    description="Analyses Grafana alerts with live ClickHouse evidence and IPinfo enrichment to produce Jira Bug reports.",
    version="2.0.0",
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

    if alert.demo_mode:
        log.info("demo_mode=True — returning fallback analysis")
        return _fallback(alert, incident_started_at)

    if not OPENAI_API_KEY:
        log.warning("OPENAI_API_KEY not set — returning fallback analysis")
        return _fallback(alert, incident_started_at)

    try:
        result = _call_openai(alert, evidence)
        log.info("OpenAI analysis complete for alert: %s", alert.alert_name)
        return result
    except Exception as exc:
        log.error("OpenAI call failed (%s) — returning fallback analysis", exc)
        return _fallback(alert, incident_started_at)
