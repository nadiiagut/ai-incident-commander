"""
ClickHouse query client for the AI Incident Analyzer.

Queries the checkout_logs table for recent /checkout failures and returns
structured evidence.  Returns None on any failure so the caller can fall
back to mock evidence transparently.
"""
import base64
import json
import logging
import urllib.error
import urllib.request

_log = logging.getLogger("clickhouse-client")
_TIMEOUT_S = 10


def _auth_header(username: str, password: str) -> dict:
    """Return Basic Auth header dict when credentials are provided."""
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}
    return {}


def _run_query(url: str, sql: str, username: str, password: str) -> list[dict] | None:
    """
    Send `sql` to ClickHouse via HTTP POST and return the `data` list.

    Returns:
      list[dict]  — rows (may be empty)
      None        — any failure (error already logged at WARNING level)
    """
    _log.info("ClickHouse query | url=%s auth=%s | sql=%s",
              url, bool(username and password), sql.replace("\n", " "))
    try:
        req = urllib.request.Request(
            url,
            data=sql.encode(),
            headers={"Content-Type": "text/plain", **_auth_header(username, password)},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            payload = json.loads(resp.read())
        rows: list[dict] = payload.get("data", [])
        _log.info("ClickHouse returned %d row(s)", len(rows))
        return rows

    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        _log.warning(
            "ClickHouse HTTP %s %s | url=%s | body=%s",
            exc.code, exc.reason, url, body[:1000],
        )
        return None

    except Exception as exc:
        _log.warning("ClickHouse request failed: %s | url=%s", exc, url)
        return None


def fetch_evidence(
    query_url: str,
    database: str,
    table: str,
    username: str = "",
    password: str = "",
) -> dict | None:
    """
    Query ClickHouse for /checkout errors in the last 10 minutes.

    Return values:
      {"source": "clickhouse", "no_data": True}          query OK, 0 rows
      {"source": "clickhouse", "no_data": False, ...}    query OK, rows found
      None                                                query failed
    """
    if not query_url:
        _log.debug("CLICKHOUSE_URL not set — skipping live query")
        return None

    sql = (
        f"SELECT "
        f"toString(timestamp) AS event_timestamp, "
        f"request_id, "
        f"client_ip, "
        f"endpoint, "
        f"status_code, "
        f"error, "
        f"deployment_version, "
        f"response_time_ms "
        f"FROM {database}.{table} "
        f"WHERE endpoint = '/checkout' "
        f"AND status_code >= 500 "
        f"AND timestamp >= now() - INTERVAL 10 MINUTE "
        f"ORDER BY timestamp DESC "
        f"LIMIT 100 "
        f"FORMAT JSON"
    )

    url = f"{query_url.rstrip('/')}/"
    rows = _run_query(url, sql, username, password)
    if rows is None:
        return None
    if not rows:
        return {"source": "clickhouse", "no_data": True}
    return _build_evidence(rows)


def fetch_since(
    query_url: str,
    database: str,
    table: str,
    endpoint: str,
    since_expr: str,
    username: str = "",
    password: str = "",
) -> dict | None:
    """
    Query for status>=500 errors on `endpoint` from `since_expr` until now.

    `since_expr` is a ClickHouse SQL expression, e.g.:
      - "toDateTime64('2026-05-10 09:30:00.000', 3, 'UTC')"
      - "now() - INTERVAL 5 MINUTE"

    Returns same shape as fetch_evidence, or None on failure.
    """
    if not query_url:
        return None

    safe_endpoint = endpoint.replace("'", "").replace("\\", "")

    sql = (
        f"SELECT "
        f"toString(timestamp) AS event_timestamp, "
        f"request_id, "
        f"client_ip, "
        f"endpoint, "
        f"status_code, "
        f"error, "
        f"deployment_version, "
        f"response_time_ms "
        f"FROM {database}.{table} "
        f"WHERE endpoint = '{safe_endpoint}' "
        f"AND status_code >= 500 "
        f"AND timestamp >= {since_expr} "
        f"ORDER BY timestamp DESC "
        f"LIMIT 500 "
        f"FORMAT JSON"
    )

    url = f"{query_url.rstrip('/')}/"
    rows = _run_query(url, sql, username, password)
    if rows is None:
        return None
    if not rows:
        return {"source": "clickhouse", "no_data": True}
    return _build_evidence(rows)


def _build_evidence(rows: list[dict]) -> dict:
    timestamps = sorted(r["event_timestamp"] for r in rows if r.get("event_timestamp"))
    first_seen = timestamps[0] if timestamps else ""
    latest_seen = timestamps[-1] if timestamps else ""

    error_counts: dict[str, int] = {}
    for r in rows:
        e = r.get("error") or "unknown"
        error_counts[e] = error_counts.get(e, 0) + 1
    dominant_error = max(error_counts, key=lambda k: error_counts[k]) if error_counts else "unknown"

    versions = sorted({r.get("deployment_version", "") for r in rows if r.get("deployment_version")})

    ip_counts: dict[str, int] = {}
    for r in rows:
        ip = r.get("client_ip", "")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    return {
        "source": "clickhouse",
        "no_data": False,
        "failed_request_count": len(rows),
        "first_seen": first_seen,
        "latest_seen": latest_seen,
        "dominant_error": dominant_error,
        "deployment_versions": versions,
        "ip_counts": ip_counts,
        "unique_ips": list(ip_counts.keys()),
        "recent_sample": rows[:5],
    }
