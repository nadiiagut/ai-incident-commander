"""
Synthetic traffic generator for the AI Incident Commander demo.

Sends GET /checkout requests with a fixed pool of X-Forwarded-For IPs chosen
from multiple countries, so ClickHouse logs carry realistic client_ip diversity
and IPinfo enrichment produces meaningful country/ASN breakdowns.

─── Traffic modes ────────────────────────────────────────────────────────────

  Manual (default)  — pick one user class via CLI:

    locust -f locustfile.py NormalUser   --host http://localhost:8000
    locust -f locustfile.py IncidentUser --host http://localhost:8000

  Auto demo shape  — set TRAFFIC_MODE=demo to activate a DemoShape that
  automatically cycles Normal → Incident → Recovery:

    TRAFFIC_MODE=demo locust -f locustfile.py --host http://localhost:8000

─── Configuring the target host ──────────────────────────────────────────────

  Priority (highest → lowest):
    1. --host CLI flag
    2. LOCUST_HOST environment variable
    3. Hard-coded default: http://localhost:8000
"""

import os
import random

from locust import HttpUser, between, task

# ── Demo IP pool ───────────────────────────────────────────────────────────────
# Fixed set of well-known public IPs spanning multiple countries and ASNs.
# Every request picks one at random so ClickHouse and IPinfo see geographic
# variety without needing real users.
DEMO_IPS: list[str] = [
    # North America
    "8.8.8.8",         # US — Google (AS15169)
    "1.1.1.1",         # US — Cloudflare (AS13335)
    "9.9.9.9",         # US — Quad9 (AS19281)
    "208.67.222.222",  # US — Cisco OpenDNS (AS36692)
    # Europe
    "77.88.8.8",       # RU — Yandex (AS13238)
    "84.200.69.80",    # DE — DNS.WATCH (AS50629)
    "185.228.168.9",   # GB — CleanBrowsing (AS60186)
    "194.242.2.2",     # DE — Mullvad (AS39351)
    # Asia-Pacific
    "168.126.63.1",    # KR — KT (AS4766)
    "103.86.96.100",   # SG — NordVPN (AS62179)
    "139.99.120.117",  # AU — OVH (AS16276)
    # Africa / South America
    "196.216.2.2",     # ZA — TENET (AS2018)
    "200.221.11.101",  # BR — Embratel (AS4230)
]


# ── Base user ──────────────────────────────────────────────────────────────────

class CheckoutUser(HttpUser):
    """
    Base class — sends GET /checkout with a randomly-chosen X-Forwarded-For IP.

    Both 200 (healthy) and 500 (incident mode) are treated as expected outcomes
    so Locust statistics stay clean regardless of the service's failure toggle.
    """

    abstract = True
    host = os.getenv("LOCUST_HOST", "http://localhost:8000")

    @task
    def checkout(self) -> None:
        ip = random.choice(DEMO_IPS)
        with self.client.get(
            "/checkout",
            headers={"X-Forwarded-For": ip},
            catch_response=True,
            name="/checkout",
        ) as resp:
            if resp.status_code in (200, 500):
                resp.success()
            else:
                resp.failure(f"Unexpected status {resp.status_code}")


# ── Traffic profiles ───────────────────────────────────────────────────────────

class NormalUser(CheckoutUser):
    """
    Steady baseline traffic — roughly 1 request/second per user.

    Use this for background load that keeps ClickHouse logs flowing without
    overwhelming the service or making the Grafana panels hard to read.
    """

    abstract = False
    wait_time = between(0.8, 1.5)


class IncidentUser(CheckoutUser):
    """
    Elevated traffic for incident simulation — roughly 10 requests/second per user.

    Use this after toggle-failure to fill ClickHouse quickly with 500 rows so
    /analyze-incident and /monitor-incident have rich evidence within seconds.
    """

    abstract = False
    wait_time = between(0.05, 0.15)


# ── Optional automated demo shape ─────────────────────────────────────────────
# Only active when TRAFFIC_MODE=demo is set.
# Cycles through three phases automatically, then stops.
#
#   Phase       Elapsed    Users   Spawn rate
#   ----------  ---------  ------  ----------
#   Normal       0 – 2 min     5       2 / s
#   Incident    2 – 5 min     30      10 / s
#   Recovery    5 – 7 min      5       5 / s

if os.getenv("TRAFFIC_MODE") == "demo":
    from locust import LoadTestShape  # noqa: E402 — conditional import by design

    class DemoShape(LoadTestShape):
        """
        Automatic load progression for the demo scenario.
        Pair this with toggle-failure at the 2-minute mark to see real 500s
        appear in ClickHouse during the Incident phase.
        """

        stages = [
            {"duration": 120, "users":  5, "spawn_rate":  2},  # Normal
            {"duration": 300, "users": 30, "spawn_rate": 10},  # Incident
            {"duration": 420, "users":  5, "spawn_rate":  5},  # Recovery
        ]

        def tick(self) -> tuple[int, float] | None:
            run_time = self.get_run_time()
            for stage in self.stages:
                if run_time < stage["duration"]:
                    return stage["users"], stage["spawn_rate"]
            return None  # all stages done — stop the test
