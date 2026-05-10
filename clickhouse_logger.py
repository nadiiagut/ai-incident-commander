"""
Best-effort ClickHouse log writer for demo-edge-service.

Reads endpoint config from environment at import time.
All errors are logged locally and swallowed — ClickHouse unavailability
must never affect the user-facing request.
"""
import base64
import json
import logging
import os
import urllib.parse
import urllib.request

_log = logging.getLogger("clickhouse-logger")

CLICKHOUSE_URL: str = os.getenv("CLICKHOUSE_URL", "")
CLICKHOUSE_DATABASE: str = os.getenv("CLICKHOUSE_DATABASE", "incident_demo")
CLICKHOUSE_TABLE: str = os.getenv("CLICKHOUSE_TABLE", "checkout_logs")
CLICKHOUSE_USERNAME: str = os.getenv("CLICKHOUSE_USERNAME", "")
CLICKHOUSE_PASSWORD: str = os.getenv("CLICKHOUSE_PASSWORD", "")

_TIMEOUT_S = 3


def _auth_headers() -> dict:
    """Return Basic Auth header dict when credentials are configured."""
    if CLICKHOUSE_USERNAME and CLICKHOUSE_PASSWORD:
        token = base64.b64encode(
            f"{CLICKHOUSE_USERNAME}:{CLICKHOUSE_PASSWORD}".encode()
        ).decode()
        return {"Authorization": f"Basic {token}"}
    return {}


def insert(event: dict) -> None:
    """
    Insert one structured log event into ClickHouse via the HTTP interface.

    Uses INSERT … FORMAT JSONEachRow with a single JSON line as the body.
    Never raises — all failures are emitted as local WARNING log lines.
    No-op when CLICKHOUSE_URL is not set.
    """
    if not CLICKHOUSE_URL:
        return

    query = f"INSERT INTO {CLICKHOUSE_DATABASE}.{CLICKHOUSE_TABLE} FORMAT JSONEachRow"
    url = f"{CLICKHOUSE_URL.rstrip('/')}/?{urllib.parse.urlencode({'query': query})}"
    body = (json.dumps(event) + "\n").encode()

    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/x-ndjson", **_auth_headers()},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            if resp.status >= 400:
                _log.warning(
                    "ClickHouse insert returned HTTP %s for request_id=%s",
                    resp.status,
                    event.get("request_id"),
                )
    except Exception as exc:
        _log.warning(
            "ClickHouse insert failed: %s (request_id=%s)",
            exc,
            event.get("request_id"),
        )
