import json
import logging
import os
import pathlib
import shutil
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import clickhouse_client
import ipinfo_client
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, RedirectResponse
from openai import OpenAI
from pydantic import BaseModel, Field

_HERE = pathlib.Path(__file__).parent

# ── Configuration ──────────────────────────────────────────────────────────────
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
CLICKHOUSE_URL: str = os.getenv("CLICKHOUSE_URL", "")
CLICKHOUSE_DATABASE: str = os.getenv("CLICKHOUSE_DATABASE", "incident_demo")
CLICKHOUSE_TABLE: str = os.getenv("CLICKHOUSE_TABLE", "checkout_logs")
CLICKHOUSE_USERNAME: str = os.getenv("CLICKHOUSE_USERNAME", "")
CLICKHOUSE_PASSWORD: str = os.getenv("CLICKHOUSE_PASSWORD", "")
IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")
MONITOR_LOOKBACK_SECONDS: int = int(os.getenv("MONITOR_LOOKBACK_SECONDS", "300"))

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
        "Config | OPENAI_MODEL=%r  openai_key_set=%s  ipinfo_token_set=%s  monitor_lookback_s=%d",
        OPENAI_MODEL, bool(OPENAI_API_KEY), bool(IPINFO_TOKEN), MONITOR_LOOKBACK_SECONDS,
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
    follow_up_count: int = Field(default=1, description="Current follow-up iteration (1-based)")
    max_followups: int = Field(default=3, description="Maximum number of follow-up checks")


class MonitorEvidence(BaseModel):
    """Raw metrics collected during the monitoring check."""

    total_failed_requests_since_incident_start: int
    failed_requests_last_5m: int
    first_seen: str
    latest_failed_request: str
    dominant_error: str
    top_country: str
    top_asn: str
    follow_up_count: int = Field(default=1, description="Echoed from request for n8n loop tracking")
    impact_pattern: str = Field(default="", description="IPinfo-derived impact pattern description")


class MonitorResponse(BaseModel):
    """Response returned by POST /monitor-incident."""

    jira_issue_key: str
    incident_status: str = Field(..., description="still_failing | recovered | monitoring_failed")
    status_summary: str
    jira_comment: str
    evidence: MonitorEvidence
    workflow_action: str = Field(
        ...,
        description="continue_monitoring | stop_recovered | stop_max_followups | stop_monitoring_failed",
    )
    should_continue_monitoring: bool = Field(
        ..., description="Whether n8n should schedule another follow-up check",
    )


# ── War Room models ────────────────────────────────────────────────────────────────

class WarRoomRequest(AlertPayload):
    """Extended request body for POST /analyze-war-room."""

    jira_issue_key: str = Field(default="", description="Existing Jira issue key (optional)")


class OwnerActionItem(BaseModel):
    owner: str = Field(..., description="Team or person responsible")
    action: str = Field(..., description="Specific action to take")
    priority: str = Field(default="high", description="high | medium | low")


class WarRoomAnalysis(BaseModel):
    """Rich structured analysis for war room sessions."""

    incident_status: str = Field(..., description="active | recovering | resolved | unknown")
    executive_summary: str = Field(..., description="2–3 sentence non-technical summary for VP/CTO")
    customer_impact: str = Field(..., description="Customer-facing impact description")
    probable_root_cause: str = Field(..., description="Most likely technical root cause")
    confidence_percent: int = Field(..., ge=0, le=100, description="Root cause confidence 0–100")
    affected_systems: list[str] = Field(..., description="Affected service and system names")
    engineering_evidence: list[str] = Field(..., description="Key technical observations from logs")
    regression_suspicion: str = Field(..., description="Regression assessment and change correlation")
    recommended_actions: list[str] = Field(..., description="Ordered remediation steps for engineers")
    owner_action_items: list[OwnerActionItem] = Field(..., description="Owner-assigned action items")
    stakeholder_update: str = Field(..., description="Ready-to-send Slack/email update for stakeholders")
    next_update_recommendation: str = Field(..., description="When to post the next stakeholder update")
    jira_comment: str = Field(..., description="Ready-to-post Jira comment for war room status")


# ── kubectl evidence models ────────────────────────────────────────────────────────

class EvidenceRequest(BaseModel):
    """Request body for POST /collect-evidence."""

    service: str = Field(..., description="Service / deployment name")
    namespace: str = Field(..., description="Kubernetes namespace")
    alert_name: str = Field(default="", description="Alert that triggered evidence collection")
    alert_time: str = Field(default="", description="Alert fire time — ISO 8601")


class KubeEvidenceBundle(BaseModel):
    """Compact Kubernetes evidence bundle returned by POST /collect-evidence."""

    service: str
    namespace: str
    alert_name: str
    alert_time: str
    collected_at: str
    kubectl_available: bool
    pods: list = Field(default_factory=list, description="Summarised pod info")
    events: list = Field(default_factory=list, description="Last 20 namespace events")
    rollout_status: str | None = None
    rollout_history: str | None = None
    recent_pod: str | None = None
    logs: str | None = None
    errors: list[str] = Field(default_factory=list)


# ── War Room monitor models ────────────────────────────────────────────────────────

class WarRoomMonitorRequest(BaseModel):
    """Request body for POST /monitor-war-room."""

    service: str = Field(default="checkout-api")
    endpoint: str = Field(default="/checkout")
    namespace: str = Field(default="ai-war-room-demo")
    incident_started_at: str = Field(..., description="ISO 8601 incident start timestamp")
    jira_issue_key: str = Field(..., description="Jira issue key, e.g. INC-42")
    alert_name: str = Field(default="")
    original_suspected_cause: str = Field(
        default="", description="Root cause from initial war room analysis"
    )
    follow_up_count: int = Field(default=1, description="Current follow-up iteration (1-based)")
    max_followups: int = Field(default=5)
    kube_evidence: KubeEvidenceBundle | None = Field(
        default=None, description="Optional Kubernetes evidence bundle from /collect-evidence"
    )


class WarRoomFollowUp(BaseModel):
    """Rich follow-up response for POST /monitor-war-room."""

    jira_issue_key: str
    incident_status: str = Field(..., description="still_failing | recovered | monitoring_failed")
    pod_readiness: str | None = Field(default=None, description="Pod readiness from Kubernetes evidence")
    error_rate_summary: str = Field(..., description="Current error rate from ClickHouse")
    cause_still_valid: str = Field(..., description="Assessment of whether original suspected cause holds")
    stakeholder_summary: str = Field(..., description="Updated message for Slack/email")
    recommended_next_step: str = Field(..., description="What engineering should do next")
    jira_comment: str = Field(..., description="Follow-up update or final recovery summary for Jira")
    should_continue_monitoring: bool
    workflow_action: str = Field(
        ...,
        description="continue_monitoring | stop_recovered | stop_max_followups | stop_monitoring_failed",
    )
    evidence: MonitorEvidence
    follow_up_count: int


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
        'Recent Log Sample (last 5 rows as bullets), Recommended Immediate Actions '
        '(evidence-driven: mention deployment version and dominant error)"\n'
        "}\n\n"
        "Return ONLY the JSON object. No markdown fences, no extra text."
    )


# ── Jira description builder ──────────────────────────────────────────────────

def _format_asn_line(d: dict) -> str:
    """Render one ASN detail entry as a plain-text bullet."""
    parts = [d["asn"]]
    if d.get("as_name"):
        parts.append(d["as_name"])
    if d.get("as_domain"):
        parts.append(d["as_domain"])
    n = d["count"]
    label = " \u2014 ".join(parts)
    suffix = "s" if n != 1 else ""
    return f"- {label}: {n} failed request{suffix}"


def _build_jira_description(alert: AlertPayload, evidence: dict, started: str) -> str:
    """
    Build plain-text Jira description using real evidence when available.
    Uppercase section titles, no wiki/markdown markers.
    """
    has_live = evidence.get("source") == "clickhouse" and not evidence.get("no_data")
    deploy_ref = (
        ", ".join(evidence.get("deployment_versions", [])) or None
    ) if has_live else None

    # ── INCIDENT SUMMARY ──────────────────────────────────────────────────────
    summary_line = (
        f"Elevated {alert.severity} errors detected on {alert.service} "
        f"via Grafana alert."
    )
    header = (
        "INCIDENT SUMMARY\n\n"
        f"{summary_line}\n\n"
        f"Alert: {alert.alert_name}\n"
        f"Service: {alert.service}\n"
        f"Severity: {alert.severity}\n"
        "Status: Active\n"
    )

    # ── CLICKHOUSE LOG EVIDENCE ───────────────────────────────────────────────
    if has_live:
        count = evidence.get("failed_request_count", 0)
        first = evidence.get("first_seen") or "N/A"
        latest = evidence.get("latest_seen") or "N/A"
        dominant = evidence.get("dominant_error") or "N/A"
        versions = ", ".join(evidence.get("deployment_versions", [])) or "N/A"

        ev_section = (
            "\nCLICKHOUSE LOG EVIDENCE\n\n"
            "Query window: since incident start\n"
            f"Failed checkout requests found: {count}\n"
            f"First failure seen: {first}\n"
            f"Latest failure seen: {latest}\n"
            f"Dominant error: {dominant}\n"
            f"Deployment version: {versions}\n"
        )

        sample: list[dict] = evidence.get("recent_sample", [])
        if sample:
            bullets = ""
            for row in sample[:3]:
                ts = row.get("event_timestamp") or "N/A"
                ip = row.get("client_ip") or "N/A"
                sc = row.get("status_code", "N/A")
                err = str(row.get("error") or "N/A")[:60]
                lat = row.get("response_time_ms", "N/A")
                bullets += f"- {ts} | ip={ip} | {sc} | {err} | latency={lat}ms\n"
            recent_section = f"\nRECENT FAILED REQUESTS FROM CLICKHOUSE\n\n{bullets}"
        else:
            recent_section = ""
    else:
        ev_section = (
            "\nCLICKHOUSE LOG EVIDENCE\n\n"
            "Live ClickHouse evidence not available. "
            "See Grafana dashboard for current metrics.\n"
        )
        recent_section = ""

    # ── IPINFO LITE IMPACT ENRICHMENT ─────────────────────────────────────────
    enrichment: dict = evidence.get("enrichment", {})
    if enrichment.get("available") is not False and enrichment:
        countries: dict = enrichment.get("failures_by_country", {})
        country_names: dict = enrichment.get("country_names", {})
        country_lines = "\n".join(
            f"- {country_names.get(c, c)}: {n} failed request{'s' if n != 1 else ''}"
            for c, n in sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
        ) or "- N/A"

        asn_details: list = enrichment.get("asn_details", [])
        if asn_details:
            asn_lines = "\n".join(_format_asn_line(d) for d in asn_details[:5])
        else:
            asns: dict = enrichment.get("failures_by_asn", {})
            asn_lines = "\n".join(
                f"- {a}: {n} failed request{'s' if n != 1 else ''}"
                for a, n in sorted(asns.items(), key=lambda x: x[1], reverse=True)[:5]
            ) or "- N/A"

        interpretation = enrichment.get("impact_pattern", "")

        geo_section = (
            "\nIPINFO LITE IMPACT ENRICHMENT\n\n"
            f"Affected countries:\n{country_lines}\n\n"
            f"Affected networks / ASNs:\n{asn_lines}\n\n"
            f"Impact interpretation:\n{interpretation}\n"
        )
    elif has_live:
        geo_section = (
            "\nIPINFO LITE IMPACT ENRICHMENT\n\n"
            "IPinfo enrichment was unavailable; raw client IP evidence "
            "remains available in the ClickHouse log section.\n"
        )
    else:
        geo_section = (
            "\nIPINFO LITE IMPACT ENRICHMENT\n\n"
            "IPinfo enrichment not available.\n"
        )

    # ── RECOMMENDED IMMEDIATE ACTIONS ─────────────────────────────────────────
    b2 = (
        f"Compare failure start time with deployment {deploy_ref}."
        if deploy_ref else
        "Compare failure start time with the most recent deployment."
    )
    actions = (
        "\nRECOMMENDED IMMEDIATE ACTIONS\n\n"
        "- Check payment gateway connectivity and timeout configuration.\n"
        f"- {b2}\n"
        "- Roll back or disable the affected checkout path if failures continue.\n"
        "- Monitor checkout 5xx rate in Grafana after mitigation.\n"
        "- Keep this Jira Bug open until automated follow-up confirms recovery."
    )
    return header + ev_section + recent_section + geo_section + actions


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


# ── War Room prompt + OpenAI ────────────────────────────────────────────────────

_WAR_ROOM_SYSTEM_PROMPT = (
    "You are an expert AI war room facilitator for production software incidents. "
    "Analyse the evidence and produce a structured war room report for both engineering teams "
    "and executive stakeholders. "
    "Always respond with a single valid JSON object — no markdown fences, no extra text."
)


def _build_war_room_message(req: WarRoomRequest, evidence: dict) -> str:
    alert_block = json.dumps({
        "alert_name": req.alert_name,
        "service": req.service,
        "severity": req.severity,
        "status": req.status,
        "starts_at": req.starts_at,
        "dashboard_url": req.dashboard_url,
        "jira_issue_key": req.jira_issue_key,
    }, indent=2)
    evidence_block = json.dumps(evidence, indent=2)

    no_data_note = ""
    if evidence.get("no_data"):
        no_data_note = (
            "\nIMPORTANT: No matching log evidence found in ClickHouse. "
            "Do NOT fabricate evidence. State clearly that no log data is available.\n"
        )

    return (
        "Production incident in war room. Analyse the following and return ONLY a JSON object.\n\n"
        f"## Alert\n{alert_block}\n\n"
        f"{no_data_note}"
        f"## Log Evidence\n{evidence_block}\n\n"
        "## Required JSON Response Shape\n"
        "{\n"
        '  "incident_status": "active | recovering | resolved | unknown",\n'
        '  "executive_summary": "2-3 non-technical sentences suitable for VP/CTO",\n'
        '  "customer_impact": "Who is affected and how",\n'
        '  "probable_root_cause": "Most likely technical root cause from evidence",\n'
        '  "confidence_percent": 0-100 integer,\n'
        '  "affected_systems": ["service-name", "dependency"],\n'
        '  "engineering_evidence": ["observation 1 from logs", "observation 2"],\n'
        '  "regression_suspicion": "Evidence of a recent change causing this",\n'
        '  "recommended_actions": ["step 1", "step 2"],\n'
        '  "owner_action_items": [\n'
        '    {"owner": "Engineering", "action": "...", "priority": "high"},\n'
        '    {"owner": "QA", "action": "...", "priority": "medium"},\n'
        '    {"owner": "SRE/Platform", "action": "...", "priority": "high"},\n'
        '    {"owner": "Product/Customer Success", "action": "...", "priority": "medium"}\n'
        '  ],\n'
        '  "stakeholder_update": "Ready-to-send 2-3 sentence Slack/email update",\n'
        '  "next_update_recommendation": "In 15 minutes or on status change",\n'
        '  "jira_comment": "Leave as empty string — will be generated from other fields"\n'
        "}\n\n"
        "Return ONLY the JSON object. No markdown fences, no extra text."
    )


def _format_war_room_jira_comment(
    incident_status: str,
    executive_summary: str,
    customer_impact: str,
    probable_root_cause: str,
    confidence_percent: int,
    engineering_evidence: list[str],
    recommended_actions: list[str],
    owner_action_items: list[OwnerActionItem],
    stakeholder_update: str,
    next_update_recommendation: str,
) -> str:
    ev_lines = "\n".join(f"- {e}" for e in engineering_evidence)
    action_lines = "\n".join(f"{i + 1}. {a}" for i, a in enumerate(recommended_actions))
    owner_lines = "\n".join(f"- {item.owner}: {item.action}" for item in owner_action_items)
    return (
        "AI War Room Assistant \u2014 Incident Brief\n\n"
        f"Status:\n{incident_status}\n\n"
        f"Executive summary:\n{executive_summary}\n\n"
        f"Customer impact:\n{customer_impact}\n\n"
        f"Probable root cause:\n{probable_root_cause}\n\n"
        f"Confidence:\n{confidence_percent}%\n\n"
        f"Evidence:\n{ev_lines}\n\n"
        f"Recommended actions:\n{action_lines}\n\n"
        f"Owner action items:\n{owner_lines}\n\n"
        f"Stakeholder update:\n{stakeholder_update}\n\n"
        f"Next update:\n{next_update_recommendation}"
    )


def _war_room_fallback(req: WarRoomRequest, evidence: dict | None = None) -> WarRoomAnalysis:
    """Deterministic war room response for demo / no-key / LLM-error modes."""
    ev = evidence or {}
    has_live = ev.get("source") == "clickhouse" and not ev.get("no_data")

    if has_live:
        count = ev.get("failed_request_count", 0)
        dominant = ev.get("dominant_error") or "unknown"
        versions = ", ".join(ev.get("deployment_versions", [])) or "unknown"
        eng_evidence = [
            f"{count} failed /checkout requests since incident start",
            f"Dominant error: {dominant}",
            f"Deployment version(s) in window: {versions}",
        ]
        root_cause = (
            f"Live evidence shows {count} /checkout failures with dominant error '{dominant}'. "
            "Likely a downstream dependency failure or a regression in the payment gateway client."
        )
        confidence = 65
    else:
        eng_evidence = [
            "No live ClickHouse evidence available",
            "Assessment based on Grafana alert metadata only",
        ]
        root_cause = (
            "Insufficient evidence without live log data. "
            "Payment gateway timeout or a recent deployment regression is most likely."
        )
        confidence = 30

    enrichment = ev.get("enrichment", {})
    top_country = enrichment.get("top_country_name", "")
    geo_note = f" Highest impact from {top_country}." if top_country else ""

    incident_status = "active"
    executive_summary = (
        f"Service '{req.service}' is experiencing elevated checkout errors "
        f"(severity: {req.severity}, alert: {req.alert_name}). "
        "Engineering is actively investigating and preparing mitigation options."
    )
    customer_impact = (
        "Customers attempting to complete purchases are receiving errors. "
        "Checkout success rate is degraded. Revenue impact is ongoing until resolved."
    )
    recommended_actions = [
        f"Verify {req.service} pod health and recent deployment history",
        "Check payment gateway connectivity and timeout configuration",
        "Review deployment changelog for changes to the checkout path",
        "Prepare rollback to the last known-good deployment version",
        "Monitor error rate in Grafana after any mitigation action",
    ]
    owner_action_items = [
        OwnerActionItem(owner="Engineering",
                        action=f"Check pod logs and rollout status for {req.service}; prepare rollback",
                        priority="high"),
        OwnerActionItem(owner="QA",
                        action="Validate checkout flow in staging after any fix is applied",
                        priority="medium"),
        OwnerActionItem(owner="SRE/Platform",
                        action="Monitor error rate, verify rollout status, check payment gateway health",
                        priority="high"),
        OwnerActionItem(owner="Product/Customer Success",
                        action="Post status page update and notify affected customers proactively",
                        priority="medium"),
    ]
    stakeholder_update = (
        f"[War Room Update] Service '{req.service}' is experiencing checkout errors "
        f"(severity: {req.severity}).{geo_note} "
        "Engineering is investigating. Next update in 15 minutes."
    )
    next_update = "Post next update in 15 minutes or immediately on any status change."

    return WarRoomAnalysis(
        incident_status=incident_status,
        executive_summary=executive_summary,
        customer_impact=customer_impact,
        probable_root_cause=root_cause,
        confidence_percent=confidence,
        affected_systems=[req.service, "payment-gateway"],
        engineering_evidence=eng_evidence,
        regression_suspicion=(
            "Deployment version correlation pending. "
            "Compare incident start time with the most recent deployment timestamp in CI/CD."
        ),
        recommended_actions=recommended_actions,
        owner_action_items=owner_action_items,
        stakeholder_update=stakeholder_update,
        next_update_recommendation=next_update,
        jira_comment=_format_war_room_jira_comment(
            incident_status=incident_status,
            executive_summary=executive_summary,
            customer_impact=customer_impact,
            probable_root_cause=root_cause,
            confidence_percent=confidence,
            engineering_evidence=eng_evidence,
            recommended_actions=recommended_actions,
            owner_action_items=owner_action_items,
            stakeholder_update=stakeholder_update,
            next_update_recommendation=next_update,
        ),
    )


def _call_openai_war_room(req: WarRoomRequest, evidence: dict) -> WarRoomAnalysis:
    log.info("Calling OpenAI (war-room) model=%s alert=%s", OPENAI_MODEL, req.alert_name)
    client = OpenAI(api_key=OPENAI_API_KEY)
    completion = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=[
            {"role": "system", "content": _WAR_ROOM_SYSTEM_PROMPT},
            {"role": "user",   "content": _build_war_room_message(req, evidence)},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
        timeout=30,
    )
    raw = completion.choices[0].message.content
    log.info("OpenAI war-room response received (%d chars)", len(raw or ""))
    data = json.loads(raw)
    data["owner_action_items"] = [
        OwnerActionItem(**item) if isinstance(item, dict) else item
        for item in data.get("owner_action_items", [])
    ]
    result = WarRoomAnalysis(**data)
    result.jira_comment = _format_war_room_jira_comment(
        incident_status=result.incident_status,
        executive_summary=result.executive_summary,
        customer_impact=result.customer_impact,
        probable_root_cause=result.probable_root_cause,
        confidence_percent=result.confidence_percent,
        engineering_evidence=result.engineering_evidence,
        recommended_actions=result.recommended_actions,
        owner_action_items=result.owner_action_items,
        stakeholder_update=result.stakeholder_update,
        next_update_recommendation=result.next_update_recommendation,
    )
    return result


# ── Monitor helpers ────────────────────────────────────────────────────────────

def _format_lookback_label(seconds: int) -> str:
    """Return a human-readable duration: 'last 30 seconds', 'last 2 minutes', 'last 1 hour'."""
    if seconds < 60:
        return f"last {seconds} second{'s' if seconds != 1 else ''}"
    minutes = seconds // 60
    if minutes < 60:
        return f"last {minutes} minute{'s' if minutes != 1 else ''}"
    hours = minutes // 60
    return f"last {hours} hour{'s' if hours != 1 else ''}"


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


def _build_status_summary(
    status: str, ev: MonitorEvidence, req: MonitorRequest, lookback_label: str = "last 5 minutes"
) -> str:
    if status == "still_failing":
        return (
            f"Incident {req.jira_issue_key} is still active: "
            f"{ev.failed_requests_last_5m} failures in the {lookback_label} "
            f"({ev.total_failed_requests_since_incident_start} total since incident start). "
            f"Dominant error: {ev.dominant_error or 'N/A'}."
        )
    if status == "recovered":
        return (
            f"Incident {req.jira_issue_key} appears recovered: "
            f"no {req.endpoint} 5xx responses in the {lookback_label}. "
            f"Total failures since incident start: {ev.total_failed_requests_since_incident_start}."
        )
    return f"Automated monitoring failed for incident {req.jira_issue_key}."


def _build_ipinfo_block(
    enrich_summary: dict | None,
    section_title: str = "IPinfo Lite impact",
    include_pattern: bool = True,
) -> str:
    """Build a plain-text IPinfo impact section.

    Filters out 'unknown' country/ASN entries when real data exists.
    Returns a fallback notice when no enriched records are available.
    """
    fallback = (
        f"\n{section_title}:\n"
        "IPinfo Lite enrichment was unavailable for the sampled failed requests.\n"
    )
    if not enrich_summary or not enrich_summary.get("available"):
        return fallback

    countries: dict = enrich_summary.get("failures_by_country", {})
    asn_details: list = enrich_summary.get("asn_details", [])
    known_countries = {c: n for c, n in countries.items() if c.lower() != "unknown"}
    known_asns = [d for d in asn_details if d.get("asn", "").lower() != "unknown"]

    if not known_countries and not known_asns:
        return fallback

    lines = [f"\n{section_title}:"]

    if known_countries:
        lines.append("Affected countries:")
        for code, count in sorted(known_countries.items(), key=lambda x: x[1], reverse=True)[:5]:
            word = "failed request" if count == 1 else "failed requests"
            lines.append(f"- {code}: {count} {word}")

    if known_asns:
        lines.append("Affected networks:")
        for d in known_asns[:5]:
            asn_code = d.get("asn", "")
            asn_name = d.get("as_name", "")
            count = d.get("count", 0)
            word = "failed request" if count == 1 else "failed requests"
            label = f"{asn_code} \u2014 {asn_name}" if asn_name else asn_code
            lines.append(f"- {label}: {count} {word}")

    if include_pattern:
        pattern = enrich_summary.get("impact_pattern", "")
        if pattern:
            lines.append("Impact pattern:")
            lines.append(pattern)

    return "\n".join(lines) + "\n"


def _build_jira_comment(
    status: str,
    ev: MonitorEvidence,
    req: MonitorRequest,
    enrich_summary: dict | None = None,
    workflow_action: str = "continue_monitoring",
    lookback_label: str = "last 5 minutes",
) -> str:
    header = (
        f"AI War Room Assistant \u2014 {req.jira_issue_key}\n"
        f"\nFollow-up check: {req.follow_up_count}/{req.max_followups}\n"
    )

    if workflow_action == "stop_monitoring_failed":
        return (
            header
            + "Status: automated follow-up could not complete\n"
            + "Manual verification of service health is required.\n"
            + "Automated monitoring for this incident is ending."
        )

    if workflow_action == "stop_recovered":
        ch_block = (
            "\nClickHouse monitoring:\n"
            f"No new {req.endpoint} 5xx responses were found in the {lookback_label}.\n"
            f"Total failed requests during the incident: {ev.total_failed_requests_since_incident_start}\n"
            f"Latest failed request: {ev.latest_failed_request or 'N/A'}\n"
        )
        ip_block = _build_ipinfo_block(
            enrich_summary,
            section_title="IPinfo Lite impact summary",
            include_pattern=False,
        )
        return (
            header
            + "Status: No new 5xx failures observed\n"
            + ch_block
            + ip_block
            + "\nOutcome:\n"
            + "The checkout service appears recovered. "
            + "Automated monitoring for this incident is ending.\n"
            + "No Jira status transition was performed automatically."
        )

    # Active failure state (continue_monitoring or stop_max_followups)
    ch_block = (
        "\nCLICKHOUSE MONITORING UPDATE\n"
        f"Failed requests in the {lookback_label}: {ev.failed_requests_last_5m}\n"
        f"Total failed requests since incident start: {ev.total_failed_requests_since_incident_start}\n"
        f"Dominant error: {ev.dominant_error or 'N/A'}\n"
        f"Latest failed request: {ev.latest_failed_request or 'N/A'}\n"
    )
    ip_block = _build_ipinfo_block(
        enrich_summary,
        section_title="IPinfo Lite impact",
        include_pattern=True,
    )

    if workflow_action == "stop_max_followups":
        return (
            header
            + "Status: incident remains active\n"
            + ch_block
            + ip_block
            + "\nOutcome:\n"
            + "Maximum automated follow-up count reached.\n"
            + "Manual ownership is required from this point.\n"
            + "Automated monitoring for this incident is ending."
        )

    # continue_monitoring (default)
    return (
        header
        + "Status: incident remains active\n"
        + ch_block
        + ip_block
        + "\nNext step:\n"
        + "The workflow will continue monitoring until the incident recovers "
        + "or the maximum follow-up count is reached."
    )


def _monitor_failed(req: MonitorRequest, reason: str) -> MonitorResponse:
    log.warning("Monitor failed for %s: %s", req.jira_issue_key, reason)
    _empty_ev = MonitorEvidence(
        total_failed_requests_since_incident_start=0,
        failed_requests_last_5m=0,
        first_seen="",
        latest_failed_request="",
        dominant_error="",
        top_country="",
        top_asn="",
        follow_up_count=req.follow_up_count,
    )
    return MonitorResponse(
        jira_issue_key=req.jira_issue_key,
        incident_status="monitoring_failed",
        status_summary=f"Automated monitoring failed: {reason}",
        jira_comment=_build_jira_comment(
            "monitoring_failed", _empty_ev, req,
            workflow_action="stop_monitoring_failed",
        ),
        evidence=_empty_ev,
        workflow_action="stop_monitoring_failed",
        should_continue_monitoring=False,
    )


# ── kubectl helpers ───────────────────────────────────────────────────────────────

def _kubectl(args: list[str], timeout: int = 15) -> tuple[str, str | None]:
    """Run a kubectl sub-command. Returns (stdout, error_message | None)."""
    try:
        result = subprocess.run(
            ["kubectl"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return "", result.stderr.strip() or f"kubectl exited {result.returncode}"
        return result.stdout.strip(), None
    except FileNotFoundError:
        return "", "kubectl not found in PATH"
    except subprocess.TimeoutExpired:
        return "", f"kubectl timed out after {timeout}s"
    except Exception as exc:
        return "", str(exc)


def _summarize_pods(pods_json: str) -> list[dict]:
    """Compact pod summary from kubectl get pods -o json output."""
    try:
        items = json.loads(pods_json).get("items", [])
        result = []
        for item in items:
            meta = item.get("metadata", {})
            status = item.get("status", {})
            cstats = status.get("containerStatuses", [])
            ready = sum(1 for c in cstats if c.get("ready", False))
            result.append({
                "name": meta.get("name", ""),
                "phase": status.get("phase", ""),
                "ready": f"{ready}/{len(cstats)}",
                "node": item.get("spec", {}).get("nodeName", ""),
                "created": meta.get("creationTimestamp", ""),
            })
        return result
    except Exception:
        return []


def _find_recent_pod(pods_json: str) -> str | None:
    """Return the most recently created Running pod name, or any pod if none are Running."""
    try:
        items = json.loads(pods_json).get("items", [])
        running = [p for p in items if p.get("status", {}).get("phase") == "Running"]
        candidates = running or items
        if not candidates:
            return None
        newest = sorted(
            candidates,
            key=lambda p: p.get("metadata", {}).get("creationTimestamp", ""),
            reverse=True,
        )
        return newest[0]["metadata"]["name"]
    except Exception:
        return None


def _summarize_events(events_json: str) -> list[dict]:
    """Compact event summary from kubectl get events -o json, last 20 entries."""
    try:
        items = json.loads(events_json).get("items", [])
        result = []
        for item in items:
            result.append({
                "type": item.get("type", ""),
                "reason": item.get("reason", ""),
                "object": item.get("involvedObject", {}).get("name", ""),
                "message": (item.get("message") or "")[:200],
                "count": item.get("count", 1),
                "last_time": item.get("lastTimestamp") or item.get("eventTime", ""),
            })
        return result[-20:]
    except Exception:
        return []


# ── War Room monitor helpers ───────────────────────────────────────────────────────

def _extract_pod_readiness(kube: KubeEvidenceBundle | None) -> str | None:
    """Summarise pod readiness from a KubeEvidenceBundle, or None if unavailable."""
    if not kube or not kube.kubectl_available or not kube.pods:
        return None
    parts = []
    for pod in kube.pods:
        name = pod.get("name", "?")
        phase = pod.get("phase", "?")
        ready = pod.get("ready", "?")
        parts.append(f"{name}: {phase} ({ready} ready)")
    return "; ".join(parts) if parts else "No pods found"


def _assess_cause_validity(
    original_cause: str,
    current_dominant_error: str,
    still_failing: bool,
) -> str:
    """Compare original suspected cause against the current dominant error."""
    if not still_failing:
        return "Incident has recovered — original cause assessment no longer critical."
    if not original_cause:
        return "No original cause specified for comparison."
    if current_dominant_error and current_dominant_error.lower() in original_cause.lower():
        return (
            f"Still valid: dominant error '{current_dominant_error}' "
            "matches the original suspected cause. No significant change in failure pattern."
        )
    if current_dominant_error:
        return (
            f"Potentially updated: current dominant error is '{current_dominant_error}', "
            "which may differ from the originally suspected cause. Consider re-evaluating."
        )
    return "Unable to assess — no error data available in current monitoring window."


def _format_war_room_followup_comment(
    follow_up_count: int,
    incident_status: str,
    pod_readiness: str | None,
    error_rate_summary: str,
    cause_still_valid: str,
    stakeholder_summary: str,
    recommended_next_step: str,
) -> str:
    pod_section = pod_readiness or "Kubernetes evidence not available"
    return (
        f"AI War Room Assistant \u2014 Follow-up Update #{follow_up_count}\n\n"
        f"Status:\n{incident_status}\n\n"
        f"Pod readiness:\n{pod_section}\n\n"
        f"Current error rate:\n{error_rate_summary}\n\n"
        f"Root cause assessment:\n{cause_still_valid}\n\n"
        f"Stakeholder update:\n{stakeholder_summary}\n\n"
        f"Recommended next step:\n{recommended_next_step}"
    )


def _format_recovery_comment(
    jira_issue_key: str,
    alert_name: str,
    service: str,
    incident_started_at: str,
    recovered_at: str,
    original_suspected_cause: str,
    total_failed: int,
    latest_failed: str,
    lookback_label: str,
    follow_up_count: int,
) -> str:
    try:
        start_str = incident_started_at.rstrip("Z").replace("T", " ")
        end_str = recovered_at.rstrip("Z").replace("T", " ")
        secs = int((datetime.fromisoformat(end_str) - datetime.fromisoformat(start_str)).total_seconds())
        if secs < 60:
            duration = f"{secs}s"
        elif secs < 3600:
            duration = f"{secs // 60}m {secs % 60}s"
        else:
            hours, rem = divmod(secs, 3600)
            duration = f"{hours}h {rem // 60}m"
    except Exception:
        duration = "unknown"

    cause_section = original_suspected_cause or "Not specified"
    checks = f"{follow_up_count} follow-up check{'s' if follow_up_count != 1 else ''}"
    return (
        f"AI War Room Assistant \u2014 Recovery Confirmed\n\n"
        f"Incident: {jira_issue_key}\n"
        f"Service: {service}\n"
        f"Recovered at: {recovered_at}\n"
        f"Incident duration: {duration}\n"
        f"Follow-up checks completed: {follow_up_count}\n\n"
        f"Recovery summary:\n"
        f"No failed requests detected in the {lookback_label}. "
        f"Service '{service}' has returned to normal operation.\n\n"
        f"Original suspected cause:\n{cause_section}\n\n"
        f"Evidence at recovery:\n"
        f"- Total failed requests since incident start: {total_failed}\n"
        f"- Last failure observed: {latest_failed or 'N/A'}\n"
        f"- Failed requests in last monitoring window: 0\n\n"
        f"Automated monitoring confirmed recovery after {checks}. "
        "Please verify with the team and close the incident if appropriate."
    )


def _war_room_monitor_failed(req: WarRoomMonitorRequest, reason: str) -> WarRoomFollowUp:
    log.warning("War room monitor failed for %s: %s", req.jira_issue_key, reason)
    _empty_ev = MonitorEvidence(
        total_failed_requests_since_incident_start=0,
        failed_requests_last_5m=0,
        first_seen="",
        latest_failed_request="",
        dominant_error="",
        top_country="",
        top_asn="",
        follow_up_count=req.follow_up_count,
    )
    return WarRoomFollowUp(
        jira_issue_key=req.jira_issue_key,
        incident_status="monitoring_failed",
        pod_readiness=_extract_pod_readiness(req.kube_evidence),
        error_rate_summary=f"Monitoring failed: {reason}",
        cause_still_valid="Unable to assess — monitoring infrastructure error.",
        stakeholder_summary=(
            f"[War Room Update] Automated monitoring check #{req.follow_up_count} "
            f"could not complete ({reason}). Manual review required."
        ),
        recommended_next_step=(
            "Investigate monitoring infrastructure and perform a manual incident assessment."
        ),
        jira_comment=(
            f"AI War Room Assistant \u2014 Monitoring Check Failed\n\n"
            f"Follow-up #{req.follow_up_count} could not complete: {reason}\n"
            "Manual review is required."
        ),
        should_continue_monitoring=False,
        workflow_action="stop_monitoring_failed",
        evidence=_empty_ev,
        follow_up_count=req.follow_up_count,
    )


# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI War Room Assistant",
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

    lookback_label = _format_lookback_label(MONITOR_LOOKBACK_SECONDS)
    recent_expr = f"now() - INTERVAL {MONITOR_LOOKBACK_SECONDS} SECOND"
    recent_ev = clickhouse_client.fetch_since(
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE,
        req.endpoint, recent_expr,
        CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD,
    )
    if recent_ev is None:
        return _monitor_failed(req, "ClickHouse query failed (5-minute window)")

    total_failed = 0 if full_ev.get("no_data") else full_ev["failed_request_count"]
    last_5m = 0 if recent_ev.get("no_data") else recent_ev["failed_request_count"]
    latest_ts = "" if full_ev.get("no_data") else full_ev.get("latest_seen", "")
    dominant_error = "" if full_ev.get("no_data") else full_ev.get("dominant_error", "")

    enrich_summary: dict | None = None
    top_country = ""
    top_asn = ""
    if not full_ev.get("no_data") and full_ev.get("unique_ips"):
        raw = ipinfo_client.enrich_ips(full_ev["unique_ips"][:20], IPINFO_TOKEN)
        if raw:
            enrich_summary = ipinfo_client.summarize_enrichment(full_ev["ip_counts"], raw)
            top_country = enrich_summary.get("top_country_name") or ""
            top_asn = enrich_summary.get("top_affected_asn", "")

    # ── Decision: recovery is based solely on recent window ───────────────────
    if last_5m == 0:
        status = "recovered"
        workflow_action = "stop_recovered"
        should_continue = False
    elif req.follow_up_count >= req.max_followups:
        status = "still_failing"
        workflow_action = "stop_max_followups"
        should_continue = False
    else:
        status = "still_failing"
        workflow_action = "continue_monitoring"
        should_continue = True

    enr = enrich_summary or {}
    log.info(
        "Monitor | %s recent_failed_requests=%d total_failed_since_start=%d "
        "incident_status=%s workflow_action=%s should_continue=%s "
        "follow_up=%d/%d top_country=%r top_asn=%r enriched_req=%d unknown_req=%d",
        req.jira_issue_key, last_5m, total_failed,
        status, workflow_action, should_continue,
        req.follow_up_count, req.max_followups,
        top_country, top_asn,
        enr.get("enriched_request_count", 0),
        enr.get("unknown_request_count", 0),
    )

    first_seen = "" if full_ev.get("no_data") else full_ev.get("first_seen", "")
    impact_pattern = enr.get("impact_pattern", "")

    evidence = MonitorEvidence(
        total_failed_requests_since_incident_start=total_failed,
        failed_requests_last_5m=last_5m,
        first_seen=first_seen,
        latest_failed_request=latest_ts,
        dominant_error=dominant_error,
        top_country=top_country,
        top_asn=top_asn,
        follow_up_count=req.follow_up_count,
        impact_pattern=impact_pattern,
    )
    return MonitorResponse(
        jira_issue_key=req.jira_issue_key,
        incident_status=status,
        status_summary=_build_status_summary(status, evidence, req, lookback_label),
        jira_comment=_build_jira_comment(status, evidence, req, enrich_summary, workflow_action, lookback_label),
        evidence=evidence,
        workflow_action=workflow_action,
        should_continue_monitoring=should_continue,
    )


# ── War Room endpoint ──────────────────────────────────────────────────────────────

@app.post(
    "/analyze-war-room",
    response_model=WarRoomAnalysis,
    summary="War room analysis — richer structured output for incident command",
)
def analyze_war_room(req: WarRoomRequest) -> WarRoomAnalysis:
    log.info("War room analysis: %s | service=%s severity=%s demo_mode=%s",
             req.alert_name, req.service, req.severity, req.demo_mode)

    evidence = _fetch_log_evidence(req.service)
    log.info(
        "War room evidence: source=%s failed_count=%s dominant_error=%r",
        evidence.get("source"),
        evidence.get("failed_request_count", "n/a"),
        evidence.get("dominant_error", "n/a"),
    )

    if req.demo_mode:
        log.info("demo_mode=True — using war room fallback with live evidence")
        return _war_room_fallback(req, evidence)

    if not OPENAI_API_KEY:
        log.warning("OPENAI_API_KEY not set — using war room fallback with live evidence")
        return _war_room_fallback(req, evidence)

    try:
        result = _call_openai_war_room(req, evidence)
        log.info("War room OpenAI analysis completed for alert: %s", req.alert_name)
        return result
    except Exception as exc:
        log.error("OpenAI war-room call failed (%s) — using fallback with live evidence", exc)
        return _war_room_fallback(req, evidence)


# ── War Room monitor endpoint ─────────────────────────────────────────────────────

@app.post(
    "/monitor-war-room",
    response_model=WarRoomFollowUp,
    summary="War room follow-up check — pod readiness, cause validity, error rate, recovery summary",
)
def monitor_war_room(req: WarRoomMonitorRequest) -> WarRoomFollowUp:
    log.info("War room monitor: %s | service=%s follow_up=%d/%d",
             req.jira_issue_key, req.service, req.follow_up_count, req.max_followups)

    if not CLICKHOUSE_URL:
        return _war_room_monitor_failed(req, "CLICKHOUSE_URL not configured")

    try:
        since_ts = _parse_ts(req.incident_started_at)
    except Exception as exc:
        return _war_room_monitor_failed(req, f"Invalid incident_started_at: {exc}")

    since_expr = f"toDateTime64('{since_ts}', 3, 'UTC')"
    full_ev = clickhouse_client.fetch_since(
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE, req.endpoint, since_expr,
        CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD,
    )
    if full_ev is None:
        return _war_room_monitor_failed(req, "ClickHouse query failed (full window)")

    lookback_label = _format_lookback_label(MONITOR_LOOKBACK_SECONDS)
    recent_expr = f"now() - INTERVAL {MONITOR_LOOKBACK_SECONDS} SECOND"
    recent_ev = clickhouse_client.fetch_since(
        CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_TABLE,
        req.endpoint, recent_expr,
        CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD,
    )
    if recent_ev is None:
        return _war_room_monitor_failed(req, "ClickHouse query failed (recent window)")

    total_failed = 0 if full_ev.get("no_data") else full_ev["failed_request_count"]
    last_window = 0 if recent_ev.get("no_data") else recent_ev["failed_request_count"]
    latest_ts = "" if full_ev.get("no_data") else full_ev.get("latest_seen", "")
    dominant_error = "" if full_ev.get("no_data") else full_ev.get("dominant_error", "")
    first_seen = "" if full_ev.get("no_data") else full_ev.get("first_seen", "")

    enrich_summary: dict | None = None
    top_country = ""
    top_asn = ""
    if not full_ev.get("no_data") and full_ev.get("unique_ips"):
        raw = ipinfo_client.enrich_ips(full_ev["unique_ips"][:20], IPINFO_TOKEN)
        if raw:
            enrich_summary = ipinfo_client.summarize_enrichment(full_ev["ip_counts"], raw)
            top_country = enrich_summary.get("top_country_name") or ""
            top_asn = enrich_summary.get("top_affected_asn", "")

    # ── Decision ─────────────────────────────────────────────────────────────
    if last_window == 0:
        incident_status = "recovered"
        workflow_action = "stop_recovered"
        should_continue = False
    elif req.follow_up_count >= req.max_followups:
        incident_status = "still_failing"
        workflow_action = "stop_max_followups"
        should_continue = False
    else:
        incident_status = "still_failing"
        workflow_action = "continue_monitoring"
        should_continue = True

    evidence = MonitorEvidence(
        total_failed_requests_since_incident_start=total_failed,
        failed_requests_last_5m=last_window,
        first_seen=first_seen,
        latest_failed_request=latest_ts,
        dominant_error=dominant_error,
        top_country=top_country,
        top_asn=top_asn,
        follow_up_count=req.follow_up_count,
        impact_pattern=(enrich_summary or {}).get("impact_pattern", ""),
    )

    # ── Kubernetes pod readiness ──────────────────────────────────────────────
    pod_readiness = _extract_pod_readiness(req.kube_evidence)

    # ── Error rate summary ────────────────────────────────────────────────────
    if last_window == 0:
        error_rate_summary = f"0 failures in the {lookback_label} — no active errors detected."
    else:
        error_rate_summary = (
            f"{last_window} failed request{'s' if last_window != 1 else ''} in the {lookback_label}. "
            f"Total since incident start: {total_failed}."
        )
        if dominant_error:
            error_rate_summary += f" Dominant error: {dominant_error}."

    # ── Cause validity ────────────────────────────────────────────────────────
    cause_still_valid = _assess_cause_validity(
        req.original_suspected_cause, dominant_error, incident_status != "recovered"
    )

    recovered_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    geo_note = f" Impact highest from {top_country}." if top_country else ""

    # ── Per-status: comment, summary, next step ───────────────────────────────
    if incident_status == "recovered":
        stakeholder_summary = (
            f"[War Room Update] Good news \u2014 service '{req.service}' has recovered. "
            f"No failures detected in the {lookback_label}. "
            "Engineering is confirming and will close the incident shortly."
        )
        recommended_next_step = (
            "Confirm recovery with the on-call engineer, post a final status update to stakeholders, "
            "and close the Jira incident ticket."
        )
        jira_comment = _format_recovery_comment(
            jira_issue_key=req.jira_issue_key,
            alert_name=req.alert_name,
            service=req.service,
            incident_started_at=req.incident_started_at,
            recovered_at=recovered_at,
            original_suspected_cause=req.original_suspected_cause,
            total_failed=total_failed,
            latest_failed=latest_ts,
            lookback_label=lookback_label,
            follow_up_count=req.follow_up_count,
        )
    else:
        stakeholder_summary = (
            f"[War Room Update] Service '{req.service}' is still experiencing errors "
            f"({last_window} failure{'s' if last_window != 1 else ''} in the {lookback_label}).{geo_note} "
            "Engineering is actively investigating. Next update in 15 minutes."
        )
        if workflow_action == "stop_max_followups":
            recommended_next_step = (
                "Maximum follow-up count reached. Escalate to senior engineering leadership, "
                "consider an emergency change freeze, and schedule a manual incident review."
            )
        else:
            recommended_next_step = (
                f"Continue monitoring. Investigate '{dominant_error or 'current errors'}' \u2014 "
                f"review recent deployments and check {req.service} dependency health."
            )
        jira_comment = _format_war_room_followup_comment(
            follow_up_count=req.follow_up_count,
            incident_status=incident_status,
            pod_readiness=pod_readiness,
            error_rate_summary=error_rate_summary,
            cause_still_valid=cause_still_valid,
            stakeholder_summary=stakeholder_summary,
            recommended_next_step=recommended_next_step,
        )

    log.info(
        "War room monitor: %s status=%s last_window=%d total=%d follow_up=%d/%d pod_readiness=%r",
        req.jira_issue_key, incident_status, last_window, total_failed,
        req.follow_up_count, req.max_followups, pod_readiness,
    )

    return WarRoomFollowUp(
        jira_issue_key=req.jira_issue_key,
        incident_status=incident_status,
        pod_readiness=pod_readiness,
        error_rate_summary=error_rate_summary,
        cause_still_valid=cause_still_valid,
        stakeholder_summary=stakeholder_summary,
        recommended_next_step=recommended_next_step,
        jira_comment=jira_comment,
        should_continue_monitoring=should_continue,
        workflow_action=workflow_action,
        evidence=evidence,
        follow_up_count=req.follow_up_count,
    )


# ── Evidence endpoint ────────────────────────────────────────────────────────────

@app.post(
    "/collect-evidence",
    response_model=KubeEvidenceBundle,
    summary="Collect Kubernetes evidence for an incident (pods, events, logs, rollout)",
)
def collect_evidence(req: EvidenceRequest) -> KubeEvidenceBundle:
    collected_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    errors: list[str] = []

    if not shutil.which("kubectl"):
        log.warning("collect-evidence: kubectl not found in PATH")
        return KubeEvidenceBundle(
            service=req.service, namespace=req.namespace,
            alert_name=req.alert_name, alert_time=req.alert_time,
            collected_at=collected_at, kubectl_available=False,
            errors=["kubectl not found in PATH"],
        )

    log.info("collect-evidence: service=%s namespace=%s alert=%s",
             req.service, req.namespace, req.alert_name)

    # ── Pods ────────────────────────────────────────────────────────────────
    pods_raw, err = _kubectl(
        ["get", "pods", "-n", req.namespace, "-l", f"app={req.service}", "-o", "json"]
    )
    if err:
        errors.append(f"get pods: {err}")
        pods_raw = ""
    pods = _summarize_pods(pods_raw)
    recent_pod = _find_recent_pod(pods_raw)

    # ── Events ──────────────────────────────────────────────────────────────
    events_raw, err = _kubectl(
        ["get", "events", "-n", req.namespace, "--sort-by=.lastTimestamp", "-o", "json"]
    )
    if err:
        errors.append(f"get events: {err}")
        events_raw = ""
    events = _summarize_events(events_raw)

    # ── Rollout status ────────────────────────────────────────────────────────
    rollout_status, err = _kubectl(
        ["rollout", "status", f"deployment/{req.service}", "-n", req.namespace, "--timeout=10s"]
    )
    if err:
        errors.append(f"rollout status: {err}")
        rollout_status = None

    # ── Rollout history ───────────────────────────────────────────────────────
    rollout_history, err = _kubectl(
        ["rollout", "history", f"deployment/{req.service}", "-n", req.namespace]
    )
    if err:
        errors.append(f"rollout history: {err}")
        rollout_history = None

    # ── Logs from most recent pod ─────────────────────────────────────────────
    logs: str | None = None
    if recent_pod:
        logs_raw, err = _kubectl(
            ["logs", recent_pod, "-n", req.namespace, "--tail=100", "--timestamps=true"]
        )
        if err:
            errors.append(f"logs ({recent_pod}): {err}")
        else:
            logs = logs_raw or "(no log output)"
    else:
        errors.append("logs: no matching pod found")

    log.info(
        "collect-evidence: service=%s namespace=%s pods=%d events=%d recent_pod=%r errors=%d",
        req.service, req.namespace, len(pods), len(events), recent_pod, len(errors),
    )

    return KubeEvidenceBundle(
        service=req.service,
        namespace=req.namespace,
        alert_name=req.alert_name,
        alert_time=req.alert_time,
        collected_at=collected_at,
        kubectl_available=True,
        pods=pods,
        events=events,
        rollout_status=rollout_status,
        rollout_history=rollout_history,
        recent_pod=recent_pod,
        logs=logs,
        errors=errors,
    )


# ── Static pages ──────────────────────────────────────────────────────────────

@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/architecture-board")


@app.get("/architecture-board", response_class=HTMLResponse)
def architecture_board() -> HTMLResponse:
    """Static architecture diagram page — suitable for video intros and README screenshots."""
    return HTMLResponse(content=(_HERE / "architecture_board.html").read_text(encoding="utf-8"))
