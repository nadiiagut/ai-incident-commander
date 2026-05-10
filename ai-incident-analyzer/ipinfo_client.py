"""
IPinfo Lite IP enrichment for the AI Incident Analyzer.

Token is optional — the free tier allows limited lookups without one.
All failures are swallowed; the caller continues with raw log evidence.
"""
import json
import logging
import urllib.request

_log = logging.getLogger("ipinfo-client")
_BASE = "https://ipinfo.io"
_TIMEOUT_S = 5


def enrich_ips(ips: list[str], token: str) -> dict[str, dict]:
    """
    Fetch IPinfo data for each IP.  Silently skips failures — never raises.
    Returns a dict mapping IP -> raw IPinfo response dict.
    """
    results: dict[str, dict] = {}
    for ip in ips:
        try:
            url = f"{_BASE}/{ip}/json"
            if token:
                url += f"?token={token}"
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
                info = json.loads(resp.read())
            results[ip] = info
        except Exception as exc:
            _log.warning("IPinfo lookup failed for %s: %s", ip, exc)
    return results


def summarize_enrichment(ip_counts: dict[str, int], enrichment: dict[str, dict]) -> dict:
    """
    Derive per-country and per-ASN failure counts from raw enrichment data.

    Returns:
    {
        "available": True,
        "failures_by_country": {"US": 32, "DE": 8, ...},   # top 5
        "failures_by_asn":     {"AS15169": 32, ...},        # top 5
        "top_affected_asn":    "AS15169",
        "impact_scope":        "broad" | "concentrated",
        "unique_countries":    3,
    }
    """
    country_counts: dict[str, int] = {}
    asn_counts: dict[str, int] = {}

    for ip, count in ip_counts.items():
        info = enrichment.get(ip, {})

        country = info.get("country") or "unknown"
        country_counts[country] = country_counts.get(country, 0) + count

        org = info.get("org") or ""
        asn = org.split(" ")[0] if org else "unknown"
        asn_counts[asn] = asn_counts.get(asn, 0) + count

    top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_asns = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    unique_countries = len(country_counts)
    top_asn = top_asns[0][0] if top_asns else "unknown"

    return {
        "available": True,
        "failures_by_country": dict(top_countries),
        "failures_by_asn": dict(top_asns),
        "top_affected_asn": top_asn,
        "impact_scope": "broad" if unique_countries > 3 else "concentrated",
        "unique_countries": unique_countries,
    }
