"""
Hydrolix query client for the AI Incident Analyzer.

Sends a SQL query over Hydrolix's ClickHouse-compatible HTTP interface
and returns structured log evidence.  Returns None on any failure so
the caller can transparently fall back to mocked evidence.
"""
import json
import logging
import re
import urllib.request

_log = logging.getLogger("hydrolix-client")

# ── SQL injection guards ────────────────────────────────────────────────────────
# Service names may contain alphanumerics, hyphens, and underscores only.
_SAFE_IDENT_RE = re.compile(r"[^a-zA-Z0-9_\-]")
# Table names additionally allow dots for project.table notation.
_SAFE_TABLE_RE = re.compile(r"[^a-zA-Z0-9_\-\.]")


def _sanitize(value: str) -> str:
    return _SAFE_IDENT_RE.sub("", value)


def _sanitize_table(value: str) -> str:
    return _SAFE_TABLE_RE.sub("", value)


# ── Query builder ──────────────────────────────────────────────────────────────

def _build_query(service: str, table: str) -> str:
    """
    Return a ClickHouse SQL query that fetches recent error rows for *service*.

    Filters:
      - last 10 minutes
      - status >= 500 OR error IS NOT NULL
    Returns up to 50 rows ordered by most recent first.
    FORMAT JSON makes Hydrolix return a {"data": [...]} envelope.
    """
    safe_service = _sanitize(service)
    safe_table = _sanitize_table(table)
    return (
        f"SELECT timestamp, service, endpoint, status, error, "
        f"deployment_version, request_id "
        f"FROM {safe_table} "
        f"WHERE service = '{safe_service}' "
        f"AND timestamp >= now() - INTERVAL 10 MINUTE "
        f"AND (toUInt16OrZero(toString(status)) >= 500 OR (error IS NOT NULL AND error != '')) "
        f"ORDER BY timestamp DESC "
        f"LIMIT 50 "
        f"FORMAT JSON"
    )


# ── Version extractor ──────────────────────────────────────────────────────────

def _extract_version(rows: list[dict]) -> str | None:
    """Return the deployment_version from the most recent row that has one."""
    for row in rows:
        v = row.get("deployment_version")
        if v:
            return str(v)
    return None


# ── Public interface ───────────────────────────────────────────────────────────

def fetch_evidence(
    service: str,
    query_url: str,
    token: str,
    table: str = "logs",
) -> dict | None:
    """
    Query Hydrolix for recent error logs belonging to *service*.

    Returns a structured evidence dict on success:
    {
        "source": "hydrolix",
        "service": "checkout-api",
        "query_window": "last 10 minutes",
        "total_errors": 12,
        "recent_errors": [ ... ],          # first 10 rows
        "deployment_version": "v1.2.8",   # from most recent error row
        "last_healthy_version": None,      # not derivable from logs alone
        "error_rate": "12 errors in last 10 minutes",
    }

    Returns None if:
    - query_url or token is empty (Hydrolix not configured)
    - The HTTP request fails (network error, auth error, …)
    - Hydrolix returns 0 rows (nothing to analyse)
    In all None cases the caller should use mocked evidence.
    """
    if not query_url or not token:
        _log.debug("Hydrolix not configured — skipping live query")
        return None

    query = _build_query(service, table)
    _log.info("Querying Hydrolix for service=%s table=%s", service, table)

    try:
        req = urllib.request.Request(
            query_url,
            data=query.encode(),
            headers={
                "Content-Type": "text/plain",
                "Authorization": f"Bearer {token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read())

        rows: list[dict] = payload.get("data", [])

        if not rows:
            _log.info(
                "Hydrolix returned 0 error rows for service=%s — using mocked evidence", service
            )
            return None

        _log.info("Hydrolix returned %d error rows for service=%s", len(rows), service)
        return {
            "source": "hydrolix",
            "service": service,
            "query_window": "last 10 minutes",
            "total_errors": len(rows),
            "recent_errors": rows[:10],
            "deployment_version": _extract_version(rows),
            "last_healthy_version": None,
            "error_rate": f"{len(rows)} errors in last 10 minutes",
        }

    except Exception as exc:
        _log.warning("Hydrolix query failed: %s — using mocked evidence", exc)
        return None
