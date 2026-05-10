"""
ClickHouse query client for the AI Incident Analyzer.

Queries the checkout_logs table for recent /checkout failures and returns
structured evidence.  Returns None on any failure so the caller can fall
back to mock evidence transparently.
"""
import json
import logging
import urllib.request

_log = logging.getLogger("clickhouse-client")
_TIMEOUT_S = 10


def fetch_evidence(query_url: str, database: str, table: str) -> dict | None:
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
        f"toString(timestamp) AS timestamp, "
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
    _log.info("Querying ClickHouse: %s.%s last 10 min /checkout status>=500", database, table)

    try:
        req = urllib.request.Request(
            url,
            data=sql.encode(),
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            payload = json.loads(resp.read())

        rows: list[dict] = payload.get("data", [])

        if not rows:
            _log.info("ClickHouse returned 0 error rows")
            return {"source": "clickhouse", "no_data": True}

        _log.info("ClickHouse returned %d error rows", len(rows))
        return _build_evidence(rows)

    except Exception as exc:
        _log.warning("ClickHouse query failed: %s", exc)
        return None


def _build_evidence(rows: list[dict]) -> dict:
    timestamps = sorted(r["timestamp"] for r in rows if r.get("timestamp"))
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
