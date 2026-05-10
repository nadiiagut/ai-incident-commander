import json
import logging
import os

from fastapi import FastAPI
from openai import OpenAI
from pydantic import BaseModel, Field

# ── Configuration ──────────────────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

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
    """Structured analysis returned to n8n for Jira ticket creation."""

    incident_summary: str = Field(..., description="2–3 sentence incident summary")
    probable_root_cause: str = Field(..., description="Most likely root cause from log evidence")
    customer_impact: str = Field(..., description="How end-customers are affected right now")
    immediate_actions: list[str] = Field(..., description="Ordered list of immediate remediation steps")
    jira_incident_title: str = Field(..., description="Concise Jira Bug title (≤80 chars)")
    jira_incident_description: str = Field(..., description="Detailed Jira Bug description (Jira wiki markup)")
    preventive_story_title: str = Field(..., description="Jira Story title for preventive engineering work")
    preventive_story_description: str = Field(..., description="Story description covering root-cause fix scope")
    acceptance_criteria: list[str] = Field(..., description="Acceptance criteria items for the preventive Story")


# ── Log evidence ────────────────────────────────────────────────────────────────

def _fetch_log_evidence(service: str) -> dict:
    """
    Return recent error log evidence for *service*.

    Currently returns static mocked data.
    Will be replaced by a live ClickHouse query against incident_demo.checkout_logs.
    """
    return {
        "service": service,
        "deployment_version": "v1.2.8",
        "last_healthy_version": "v1.2.7",
        "error_rate_1m": "100%",
        "recent_errors": [
            {
                "timestamp": "2026-05-06T14:00:12Z",
                "level": "ERROR",
                "message": "payment_gateway_timeout",
                "http_status": 500,
                "deployment_version": "v1.2.8",
                "trace_id": "abc123def456",
            },
            {
                "timestamp": "2026-05-06T14:00:18Z",
                "level": "ERROR",
                "message": "payment_gateway_timeout",
                "http_status": 500,
                "deployment_version": "v1.2.8",
                "trace_id": "abc123def457",
            },
            {
                "timestamp": "2026-05-06T14:00:24Z",
                "level": "ERROR",
                "message": "payment_gateway_timeout",
                "http_status": 500,
                "deployment_version": "v1.2.8",
                "trace_id": "abc123def458",
            },
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
    return (
        "Production alert received. Analyse the following and respond with the JSON object below.\n\n"
        f"## Alert\n{alert_block}\n\n"
        f"## Log Evidence\n{evidence_block}\n\n"
        "## Required JSON Response Shape\n"
        "{\n"
        '  "incident_summary": "2-3 sentence summary of the incident and its current state",\n'
        '  "probable_root_cause": "Most likely root cause based on the evidence",\n'
        '  "customer_impact": "How end-customers are affected right now",\n'
        '  "immediate_actions": ["step 1", "step 2", "step 3"],\n'
        '  "jira_incident_title": "Concise Jira Bug title (max 80 chars)",\n'
        '  "jira_incident_description": "Detailed Jira Bug description in Jira wiki markup",\n'
        '  "preventive_story_title": "Jira Story title for preventing recurrence",\n'
        '  "preventive_story_description": "Story description — scope of the fix",\n'
        '  "acceptance_criteria": ["criterion 1", "criterion 2", "criterion 3"]\n'
        "}\n\n"
        "Return ONLY the JSON object. No markdown, no explanation."
    )


# ── Safe fallback ──────────────────────────────────────────────────────────────

def _fallback(alert: AlertPayload) -> IncidentAnalysis:
    """
    Deterministic response used when:
    - OPENAI_API_KEY is absent
    - The LLM call fails for any reason
    - demo_mode is True
    """
    return IncidentAnalysis(
        incident_summary=(
            f"Alert '{alert.alert_name}' is firing for service '{alert.service}' "
            f"with severity {alert.severity}. "
            "Log evidence shows repeated HTTP 500 payment_gateway_timeout errors "
            "starting after deployment v1.2.8."
        ),
        probable_root_cause=(
            "Deployment v1.2.8 introduced a regression in the payment gateway client. "
            "All checkout requests are failing with payment_gateway_timeout since the "
            "deployment at 14:00 UTC. v1.2.7 was the last healthy version."
        ),
        customer_impact=(
            "100% of checkout attempts are failing. Customers cannot complete purchases. "
            "Revenue impact grows linearly with time until the incident is resolved."
        ),
        immediate_actions=[
            "Rollback checkout-api to v1.2.7 immediately",
            "Verify payment gateway connectivity independently",
            "Page the on-call engineer and the release owner of v1.2.8",
            "Open a war-room channel and post status to the customer status page",
            "Monitor error rate after rollback to confirm resolution",
        ],
        jira_incident_title=f"[INCIDENT] {alert.alert_name} — {alert.service} 100% 500s",
        jira_incident_description=(
            "h2. Incident Summary\n\n"
            f"*Alert:* {alert.alert_name}\n"
            f"*Service:* {alert.service}\n"
            f"*Severity:* {alert.severity}\n"
            f"*Started:* {alert.starts_at or 'unknown'}\n"
            f"*Dashboard:* {alert.dashboard_url or 'N/A'}\n\n"
            "h2. Symptoms\n\n"
            "* 100% HTTP 500 error rate on /checkout\n"
            "* Error message: {{payment_gateway_timeout}}\n"
            "* First observed after deployment v1.2.8\n\n"
            "h2. Log Evidence\n\n"
            "||Timestamp||Message||HTTP Status||Version||\n"
            "|2026-05-06T14:00:12Z|payment_gateway_timeout|500|v1.2.8|\n"
            "|2026-05-06T14:00:18Z|payment_gateway_timeout|500|v1.2.8|\n"
            "|2026-05-06T14:00:24Z|payment_gateway_timeout|500|v1.2.8|\n\n"
            "h2. Actions Taken\n\n"
            "* _To be filled by on-call engineer_"
        ),
        preventive_story_title=(
            "Add payment-gateway circuit breaker and pre-deploy smoke test to checkout-api"
        ),
        preventive_story_description=(
            "h2. Context\n\n"
            "The v1.2.8 deployment caused a complete checkout outage due to a "
            "payment_gateway_timeout regression with no automatic circuit breaker or "
            "canary gate to catch it.\n\n"
            "h2. Scope\n\n"
            "* Implement a circuit-breaker (e.g. resilience4j / tenacity) around the "
            "payment gateway client so partial failures do not cascade to 100% error rate\n"
            "* Add a /checkout smoke test to the deployment pipeline that blocks promotion "
            "if error rate exceeds 1% after 60 s\n"
            "* Create a runbook for this alert and link it from the Grafana alert rule\n"
            "* Review and tighten the payment-gateway timeout configuration"
        ),
        acceptance_criteria=[
            "A circuit breaker trips after 5 consecutive payment gateway failures "
            "and returns a graceful error to the customer within 500 ms",
            "The deployment pipeline runs /checkout smoke test and blocks if error "
            "rate > 1% after 60 s",
            "A runbook is created, reviewed, and linked from the Grafana alert rule",
            "The incident does not recur within 30 days of the fix being deployed",
            "Payment gateway timeout value is documented and under version control",
        ],
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
    description="Analyses Grafana alerts and mocked log evidence to produce structured Jira-ready incident reports.",
    version="1.0.0",
)


@app.get("/health", summary="Liveness probe")
def health() -> dict:
    return {"status": "ok"}


@app.post(
    "/analyze-incident",
    response_model=IncidentAnalysis,
    summary="Analyse a firing alert and return a structured incident report",
)
def analyze_incident(alert: AlertPayload) -> IncidentAnalysis:
    log.info("Received alert: %s | service=%s severity=%s demo_mode=%s",
             alert.alert_name, alert.service, alert.severity, alert.demo_mode)

    evidence = _fetch_log_evidence(alert.service)

    if alert.demo_mode:
        log.info("demo_mode=True — returning fallback analysis")
        return _fallback(alert)

    if not OPENAI_API_KEY:
        log.warning("OPENAI_API_KEY not set — returning fallback analysis")
        return _fallback(alert)

    try:
        result = _call_openai(alert, evidence)
        log.info("OpenAI analysis complete for alert: %s", alert.alert_name)
        return result
    except Exception as exc:
        log.error("OpenAI call failed (%s) — returning fallback analysis", exc)
        return _fallback(alert)
