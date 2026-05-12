"""
IPinfo Lite IP enrichment for the AI Incident Analyzer.

Token is optional — the free tier allows limited lookups without one.
All failures are swallowed; the caller continues with raw log evidence.

IPinfo Lite fields used when available:
  country, country_name, continent (object or string),
  asn (object with asn/name/domain), org (legacy fallback)
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


def _parse_asn_info(info: dict) -> tuple[str, str, str]:
    """Return (asn, as_name, as_domain) from an IPinfo response dict.

    Handles both the dedicated ``asn`` object (Lite/Business tier) and the
    legacy ``org`` string "AS15169 Google LLC".
    """
    asn_obj = info.get("asn")
    if isinstance(asn_obj, dict):
        return (
            asn_obj.get("asn") or "unknown",
            asn_obj.get("name") or "",
            asn_obj.get("domain") or "",
        )
    org = info.get("org") or ""
    parts = org.split(" ", 1)
    asn = parts[0] if parts and parts[0].startswith("AS") else "unknown"
    as_name = parts[1] if len(parts) > 1 else ""
    return asn, as_name, ""


def _parse_continent(info: dict) -> str:
    """Return continent name from an IPinfo response dict (string or object)."""
    raw = info.get("continent")
    if isinstance(raw, dict):
        return raw.get("name") or raw.get("code") or ""
    if isinstance(raw, str):
        return raw
    return ""


def summarize_enrichment(ip_counts: dict[str, int], enrichment: dict[str, dict]) -> dict:
    """
    Derive per-country, per-continent, and per-ASN failure counts.

    Returns a superset of the old schema — all existing keys are preserved
    for backward compatibility; new keys are additive.

    New keys:
      country_names       dict[code, display_name]
      failures_by_continent dict[name, count]
      asn_details         list[{asn, as_name, as_domain, count}]  top 5
      unique_asns         int
      impact_pattern      str
      top_country_code    str
      top_country_name    str
      top_country_count   int
      top_asn_name        str
      top_asn_domain      str
    """
    country_counts: dict[str, int] = {}
    country_names: dict[str, str] = {}
    continent_counts: dict[str, int] = {}
    asn_counts: dict[str, int] = {}
    asn_meta: dict[str, dict] = {}
    enriched_request_count = 0
    unknown_request_count = 0

    for ip, count in ip_counts.items():
        info = enrichment.get(ip) or {}

        if not info:
            unknown_request_count += count
            continue
        enriched_request_count += count

        country_code = info.get("country") or "unknown"
        country_name = info.get("country_name") or country_code
        country_counts[country_code] = country_counts.get(country_code, 0) + count
        country_names.setdefault(country_code, country_name)

        continent = _parse_continent(info)
        if continent:
            continent_counts[continent] = continent_counts.get(continent, 0) + count

        asn, as_name, as_domain = _parse_asn_info(info)
        asn_counts[asn] = asn_counts.get(asn, 0) + count
        asn_meta.setdefault(asn, {"name": as_name, "domain": as_domain})

    top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
    top_asns = sorted(asn_counts.items(), key=lambda x: x[1], reverse=True)

    unique_countries = len(country_counts)
    unique_asns = len(asn_counts)

    # Prefer non-unknown entries when real enriched data exists
    _known_asns = [(a, n) for a, n in top_asns if a.lower() != "unknown"]
    top_asn = _known_asns[0][0] if _known_asns else (top_asns[0][0] if top_asns else "unknown")
    top_asn_meta = asn_meta.get(top_asn, {})

    _known_countries = [(c, n) for c, n in top_countries if c.lower() != "unknown"]
    _top_c = _known_countries[0] if _known_countries else (top_countries[0] if top_countries else ("unknown", 0))
    top_country_code = _top_c[0]
    top_country_name = country_names.get(top_country_code, top_country_code)
    top_country_count = _top_c[1]

    if unique_asns > 1 and unique_countries > 1:
        impact_pattern = (
            "Failures span multiple networks and countries, which suggests a broader "
            "service-side incident rather than a single-client or single-network problem."
        )
    elif unique_asns == 1 and top_asn != "unknown":
        org_name = top_asn_meta.get("name") or top_asn
        impact_pattern = (
            f"Impact appears concentrated in {org_name}, "
            "which may indicate a customer or network-specific issue."
        )
    else:
        impact_pattern = (
            "Impact concentration could not be determined from available data."
        )

    asn_details = [
        {
            "asn": asn,
            "as_name": asn_meta.get(asn, {}).get("name", ""),
            "as_domain": asn_meta.get(asn, {}).get("domain", ""),
            "count": cnt,
        }
        for asn, cnt in top_asns[:5]
    ]

    return {
        "available": True,
        # ── Legacy keys (unchanged) ────────────────────────────────────────────
        "failures_by_country": dict(top_countries[:5]),
        "failures_by_asn": dict(top_asns[:5]),
        "top_affected_asn": top_asn,
        "impact_scope": "broad" if unique_countries > 3 else "concentrated",
        "unique_countries": unique_countries,
        # ── New keys ──────────────────────────────────────────────────────────
        "country_names": country_names,
        "failures_by_continent": dict(
            sorted(continent_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ),
        "asn_details": asn_details,
        "unique_asns": unique_asns,
        "impact_pattern": impact_pattern,
        "top_country_code": top_country_code,
        "top_country_name": top_country_name,
        "top_country_count": top_country_count,
        "top_asn_name": top_asn_meta.get("name", ""),
        "top_asn_domain": top_asn_meta.get("domain", ""),
        "enriched_request_count": enriched_request_count,
        "unknown_request_count": unknown_request_count,
    }
