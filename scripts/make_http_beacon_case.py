#!/usr/bin/env python3
"""Generate a synthetic HTTP-beaconing C2 case: cases/http-beacon/.

Single-purpose and seeded, like make_dns_tunnel_case.py. Regenerate with:

    python3 scripts/make_http_beacon_case.py [--out cases/http-beacon] [--target-mb 1.0]

What is planted, and why it is planted that way:

  * A C2 beacon from ONE workstation to ONE rare external domain: a small GET every
    ~60 s with jitter, for four hours. This is deliberately the OPPOSITE timing
    signature of cases/dns-tunnel: periodic-with-jitter, not bursty sessions. A grader
    can therefore tell whether a brief's timing language is evidence-driven or a
    template -- a commander that calls this "bursty sessions" has pattern-matched the
    previous case instead of reading this one.
  * The channel does real work: a registration request carrying the encoded hostname,
    occasional larger TASKING responses, and two POST uploads with large request
    bodies -- the exfiltration. Request/response size asymmetry is the detail that
    separates a live implant from a dead poller, exactly as payload-bearing answers
    separated the live tunnel from a dead beacon.
  * **Benign decoys that defeat "periodic = C2".** Everything periodic here except the
    beacon is legitimate: OCSP refreshes, a software-update poller on a strict half-hour
    metronome, a corporate telemetry agent POSTing from EVERY host including the victim,
    and -- the trap -- a market-data widget on ONE host polling every 5 minutes. Single
    source, fixed cadence, small responses: the beacon's shape, benign. What actually
    separates the C2 is the conjunction: rare domain + high-entropy session token +
    upload asymmetry + a stale browser UA no other host runs.

GROUND_TRUTH.md is written to the case root, NOT into logs/, so the runner never reads
it. Grade with:  ./scripts/grade.py out/<run> --case cases/http-beacon
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

SEED = 20260906

# --- the scenario -------------------------------------------------------------------
C2_DOMAIN = "edge-metrics-relay.com"
C2_IP = "91.242.217.106"
VICTIM_IP = "10.12.34.73"
VICTIM_HOST = "wks-1147"
VICTIM_MAC = "00:1b:44:19:2c:5e"
VICTIM_USER = "j.lindqvist"
PROXY_PORT = 443
# The estate standard is Chrome 131; the implant embeds a build from months earlier.
BEACON_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
ESTATE_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

WINDOW_START = datetime(2026, 9, 2, 8, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)

BENIGN_HOSTS = [f"10.12.34.{n}" for n in (11, 14, 18, 22, 27, 31, 40, 44, 51, 63, 70, 88)]

BENIGN_SITES = [
    ("outlook.office365.com", "40.99.148.12"), ("teams.microsoft.com", "52.113.194.132"),
    ("www.google.com", "142.250.74.36"), ("fonts.gstatic.com", "142.250.74.67"),
    ("intranet.corp.example.com", "10.12.1.20"), ("git.corp.example.com", "10.12.1.24"),
    ("jira.corp.example.com", "10.12.1.25"), ("registry.npmjs.org", "104.16.27.34"),
    ("pypi.org", "151.101.0.223"), ("api.github.com", "140.82.121.6"),
    ("slack.com", "18.134.215.66"), ("zoom.us", "170.114.52.2"),
    ("cdn.jsdelivr.net", "151.101.1.229"), ("sharepoint.corp.example.com", "10.12.1.31"),
    ("docs.corp.example.com", "10.12.1.32"), ("mail.corp.example.com", "10.12.1.8"),
]

BENIGN_PATHS = [
    "/", "/index.html", "/api/messages", "/static/app.js", "/static/site.css",
    "/images/logo.png", "/api/v1/user/profile", "/search?q=quarterly+report",
    "/wiki/Home", "/browse/PROJ-1443", "/packages/react/-/react-18.3.1.tgz",
    "/favicon.ico", "/api/channels/list", "/calendar/day", "/files/recent",
]

HEX = "0123456789abcdef"
B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _rand_label(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _uid(ts: float, port: int) -> str:
    raw = f"{int(ts * 1e6)}{port}"
    return "".join(B32[int(c) % 32] for c in raw[-12:])


def _http_line(
    ts: float, src: str, sport: int, dst: str, method: str, host: str, uri: str,
    user_agent: str, req_len: int, resp_len: int, status: int,
) -> str:
    """Zeek http.log, tab-separated, trimmed to the fields that carry signal."""
    status_msg = {200: "OK", 204: "No Content", 304: "Not Modified", 404: "Not Found"}[status]
    return "\t".join(
        [
            f"{ts:.6f}", f"C{_uid(ts, sport)}", src, str(sport), dst, str(PROXY_PORT),
            "1", method, host, uri, "-", "1.1", user_agent,
            str(req_len), str(resp_len), str(status), status_msg,
        ]
    )


class Generator:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.rows: list[tuple[float, str]] = []
        self.ground_truth: dict[str, object] = {}

    # -- background ------------------------------------------------------------------

    def benign_traffic(self, count: int) -> None:
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            site, ip = self.rng.choice(BENIGN_SITES)
            status = self.rng.choices([200, 304, 404, 204], weights=[80, 12, 4, 4])[0]
            method = self.rng.choices(["GET", "POST"], weights=[88, 12])[0]
            req_len = 0 if method == "GET" else self.rng.randint(40, 4_000)
            resp_len = 0 if status == 304 else self.rng.randint(300, 220_000)
            self.rows.append(
                (ts, _http_line(ts, src, self.rng.randint(49152, 65535), ip, method, site,
                                self.rng.choice(BENIGN_PATHS), ESTATE_UA, req_len,
                                resp_len, status))
            )

    # -- decoys: benign, and beacon-shaped ---------------------------------------------

    def decoy_ocsp(self) -> None:
        """Certificate status checks: small, frequent-ish, from many hosts."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for src in BENIGN_HOSTS:
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, 900)
            while ts < WINDOW_START.timestamp() + span:
                self.rows.append(
                    (ts, _http_line(ts, src, self.rng.randint(49152, 65535),
                                    "184.26.11.90", "POST", "ocsp.digicert.example.com",
                                    "/", "Microsoft-CryptoAPI/10.0",
                                    self.rng.randint(80, 120), self.rng.randint(400, 900),
                                    200))
                )
                ts += self.rng.uniform(2_400, 5_200)

    def decoy_update_poller(self) -> None:
        """A software-update check on a strict half-hour metronome from every host.
        MORE regular than the beacon -- perfect periodicity is not evidence of malice."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for src in BENIGN_HOSTS:
            offset = self.rng.uniform(0, 1800)
            ts = WINDOW_START.timestamp() + offset
            while ts < WINDOW_START.timestamp() + span:
                self.rows.append(
                    (ts, _http_line(ts, src, self.rng.randint(49152, 65535),
                                    "203.119.44.7", "GET", "updates.vendor-cloud.example.net",
                                    "/catalog/v3/win64/catalog.xml", "VendorUpdate/3.11",
                                    0, self.rng.randint(1_800, 2_400), 200))
                )
                ts += 1800.0

    def decoy_corp_telemetry(self) -> None:
        """The corporate agent POSTs a metrics bundle every ten minutes from EVERY host,
        the victim included. Periodic POSTs with a payload, entirely legitimate."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for src in BENIGN_HOSTS + [VICTIM_IP]:
            offset = self.rng.uniform(0, 600)
            ts = WINDOW_START.timestamp() + offset
            while ts < WINDOW_START.timestamp() + span:
                self.rows.append(
                    (ts, _http_line(ts, src, self.rng.randint(49152, 65535),
                                    "10.12.1.40", "POST", "telemetry.corp.example.com",
                                    "/ingest/v1/host-metrics", "CorpAgent/7.4.2",
                                    self.rng.randint(1_400, 3_800),
                                    self.rng.randint(20, 40), 204))
                )
                ts += 600.0 + self.rng.uniform(-8, 8)

    def decoy_market_widget(self) -> None:
        """The trap: ONE host polls a market-data feed every five minutes. Single
        source, fixed cadence, small responses -- the beacon's silhouette, benign. The
        separators are readable URIs, a mainstream UA, no uploads, no entropy."""
        widget_host = "10.12.34.31"
        span = (WINDOW_END - WINDOW_START).total_seconds()
        ts = WINDOW_START.timestamp() + self.rng.uniform(0, 300)
        while ts < WINDOW_START.timestamp() + span:
            self.rows.append(
                (ts, _http_line(ts, widget_host, self.rng.randint(49152, 65535),
                                "198.41.209.140", "GET", "feeds.market-pulse.example.org",
                                "/api/quotes?symbols=OMXS30,SPX,NDX&fields=last,chg",
                                ESTATE_UA, 0, self.rng.randint(900, 1_400), 200))
            )
            ts += 300.0 + self.rng.uniform(-4, 4)

    # -- the beacon --------------------------------------------------------------------

    def beacon(self) -> None:
        """Periodic check-ins with jitter, tasking responses, and two POST uploads."""
        first_ts = WINDOW_START.timestamp() + 312.4
        # Registration: the hostname, base32-encoded, in the very first request. The
        # single strongest line in the case -- the analogue of dns-tunnel's NS setup.
        reg_token = "".join(B32[ord(c) % 32] for c in VICTIM_HOST) + "2