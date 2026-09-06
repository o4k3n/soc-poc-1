#!/usr/bin/env python3
"""Generate a synthetic HTTP-beaconing C2 case: cases/http-c2/.

Seeded and reproducible, the same as make_dns_tunnel_case.py. This is the SECOND graded
scenario, and it is deliberately the timing OPPOSITE of the DNS tunnel:

  * The tunnel was **bursty** -- five sessions separated by long idle gaps, because it was
    carrying real traffic. A brief that called it "regular-interval beaconing" mis-read it.
  * This C2 is **periodic** -- a check-in roughly every 60 s with jitter, continuous
    across the whole window, because that is what a beacon does. A brief that calls this
    "bursty exfiltration sessions" has mis-read it the other way.

Running both proves the commander's timing conclusions are driven by the evidence rather
than by a template. The `timeline` aggregation skill is the tool for it: on this case it
should report no idle gap exceeding the burst factor (steady), where on the tunnel it
found five bursts.

**Benign decoys that defeat "periodic to one host = C2".** Every decoy here is legitimately
periodic, which is the whole trap:

  * **OCSP/CRL checks** -- certificate validation, periodic-ish, from many hosts.
  * **Windows telemetry** -- scheduled POSTs to a Microsoft data endpoint.
  * **Update pollers** -- BITS range GETs, large *inbound* downloads.
  * **An internal monitoring agent** -- the killer decoy. It POSTs a heartbeat every
    120 s, exactly on the metronome, to an internal collector, FROM MANY HOSTS INCLUDING
    THE VICTIM. So "this host beacons on a fixed interval to one destination" is true for
    a benign reason too. What separates the C2 is not periodicity: it is the rare EXTERNAL
    destination, the anomalous hardcoded User-Agent, and the large *outbound* request
    bodies (exfil) versus the monitor's tiny heartbeats.

The discriminators are all HTTP-log-visible and citeable: destination rarity (one internal
host talking to one external IP nobody else touches), the User-Agent string, and
request_body_len (outbound volume) versus response_body_len (downloads).

GROUND_TRUTH.md is written to the case root, NOT into logs/, so analyze.py never reads it.

    python3 scripts/make_http_c2_case.py [--out cases/http-c2] [--target-mb 1.2]
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path

SEED = 20260904

# --- the scenario -------------------------------------------------------------------
C2_DOMAIN = "cdn-metric-collector.net"
C2_IP = "185.243.115.94"
VICTIM_IP = "10.12.34.72"
VICTIM_HOST = "wks-4471"
VICTIM_MAC = "00:1b:44:11:6c:d3"
VICTIM_USER = "r.holt"
# The beacon's hardcoded User-Agent: an ancient IE string, wildly out of place in 2026
# and identical on every request. Real browsers on this estate send current Chrome/Edge.
C2_USER_AGENT = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)"

# Internal monitoring collector -- the benign look-alike beacon.
MONITOR_HOST = "collector.corp.example.com"
MONITOR_IP = "10.12.34.5"
MONITOR_UA = "corp-monitor/2.4"

WINDOW_START = datetime(2026, 9, 4, 13, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 9, 4, 16, 0, 0, tzinfo=timezone.utc)

# Ordinary estate hosts. The victim is one of them; the monitoring agent runs on a subset.
BENIGN_HOSTS = [f"10.12.34.{n}" for n in (11, 14, 18, 22, 27, 31, 40, 44, 51, 63, 70, 72, 88)]
MONITORED_HOSTS = [f"10.12.34.{n}" for n in (11, 14, 22, 40, 51, 63, 72, 88)]

BENIGN_SITES = [
    ("outlook.office365.com", "/owa/", "text/html"),
    ("teams.microsoft.com", "/api/csa/presence", "application/json"),
    ("www.google.com", "/search", "text/html"),
    ("fonts.gstatic.com", "/s/roboto/v30/font.woff2", "font/woff2"),
    ("api.github.com", "/repos/corp/app/commits", "application/json"),
    ("registry.npmjs.org", "/react", "application/json"),
    ("pypi.org", "/simple/requests/", "text/html"),
    ("slack.com", "/api/rtm.connect", "application/json"),
    ("cdn.jsdelivr.net", "/npm/vue@3/dist/vue.js", "application/javascript"),
    ("intranet.corp.example.com", "/dashboard", "text/html"),
    ("jira.corp.example.com", "/browse/OPS-1421", "text/html"),
    ("git.corp.example.com", "/corp/app/-/merge_requests", "text/html"),
    ("sharepoint.corp.example.com", "/sites/ops/Shared", "text/html"),
]

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
]

HEX = "0123456789abcdef"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

_HTTP_FIELDS = (
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "trans_depth",
    "method", "host", "uri", "referrer", "version", "user_agent", "request_body_len",
    "response_body_len", "status_code", "status_msg", "resp_mime_types",
)
_HTTP_TYPES = (
    "time", "string", "addr", "port", "addr", "port", "count", "string", "string",
    "string", "string", "string", "string", "count", "count", "count", "string", "string",
)

_STATUS_MSG = {200: "OK", 204: "No Content", 206: "Partial Content", 301: "Moved Permanently",
               304: "Not Modified", 404: "Not Found"}


def _rand_label(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _uid(ts: float, port: int) -> str:
    raw = f"{int(ts * 1e6)}{port}"
    b32 = "abcdefghijklmnopqrstuvwxyz234567"
    return "C" + "".join(b32[int(c) % 32] for c in raw[-12:])


def _http_line(
    ts: float, src: str, sport: int, dst: str, dport: int, method: str, host: str,
    uri: str, ua: str, req_len: int, resp_len: int, status: int, mime: str = "text/html",
    referrer: str = "-",
) -> str:
    """One Zeek http.log record, tab-separated, in field order.

    This is a decrypting-proxy view: TLS sites appear here with host/uri/user-agent
    visible, which is what makes the User-Agent and outbound-body signals available to a
    log-only investigation. Zeek over cleartext would show the same fields.
    """
    return "\t".join(
        [
            f"{ts:.6f}", _uid(ts, sport), src, str(sport), dst, str(dport), "1", method,
            host, uri, referrer, "1.1", ua, str(req_len), str(resp_len), str(status),
            _STATUS_MSG.get(status, "OK"), mime if resp_len else "-",
        ]
    )


class Generator:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.rows: list[tuple[float, str]] = []
        self.ground_truth: dict[str, object] = {}

    # -- background ------------------------------------------------------------------

    def benign_browsing(self, count: int) -> None:
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            host, uri, mime = self.rng.choice(BENIGN_SITES)
            method = "GET" if self.rng.random() < 0.85 else "POST"
            req_len = 0 if method == "GET" else self.rng.randint(40, 900)
            status = self.rng.choice([200, 200, 200, 204, 301, 304, 404])
            resp_len = 0 if status in (204, 304) else self.rng.randint(120, 40000)
            dst = f"{self.rng.randint(20, 210)}.{self.rng.randint(0,255)}." \
                  f"{self.rng.randint(0,255)}.{self.rng.randint(1,254)}"
            self.rows.append(
                (ts, _http_line(ts, src, self.rng.randint(49152, 65535), dst, 80, method,
                                host, uri, self.rng.choice(BROWSER_UAS), req_len, resp_len,
                                status, mime))
            )

    # -- decoys: benign, and beacon-shaped -------------------------------------------

    def decoy_ocsp(self, count: int) -> None:
        """Certificate validation. Periodic-ish GETs to a CA responder, many hosts, a
        crypto-stack User-Agent. Regular but benign."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            path = "/" + _rand_label(self.rng, B64, 46).replace("/", "A")
            self.rows.append(
                (ts, _http_line(ts, src, self.rng.randint(49152, 65535), "93.184.220.29",
                                80, "GET", "ocsp.digicert.com", path,
                                "Microsoft-CryptoAPI/10.0", 0, self.rng.randint(400, 1500),
                                200, "application/ocsp-response"))
            )

    def decoy_telemetry(self, count: int) -> None:
        """Windows telemetry: scheduled POSTs to a Microsoft data endpoint, many hosts."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            self.rows.append(
                (ts, _http_line(ts, src, self.rng.randint(49152, 65535), "20.42.73.28", 80,
                                "POST", "v10.events.data.microsoft.com", "/OneCollector/1.0/",
                                "Microsoft-Delivery-Optimization/10.0",
                                self.rng.randint(300, 2200), self.rng.randint(0, 40),
                                200, "application/json"))
            )

    def decoy_update_poller(self, count: int) -> None:
        """BITS range GETs for update content: large INBOUND downloads (response bodies),
        the mirror image of the C2's large outbound uploads."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            uri = f"/d/msdownload/update/{_rand_label(self.rng, HEX, 16)}.cab"
            self.rows.append(
                (ts, _http_line(ts, src, self.rng.randint(49152, 65535), "23.55.148.10", 80,
                                "GET", "ctldl.windowsupdate.com", uri,
                                "Microsoft-BITS/7.8", 0,
                                self.rng.randint(50000, 900000),
                                self.rng.choice([200, 206]), "application/octet-stream"))
            )

    def decoy_monitoring(self, interval: float, jitter: float) -> None:
        """The killer decoy: a heartbeat POST every `interval` seconds from every monitored
        host, INCLUDING THE VICTIM, to an internal collector. Beacon-shaped by every crude
        test -- fixed interval, one destination, POST -- and entirely benign. Tiny bodies,
        internal destination, honest product User-Agent."""
        total = 0
        for host_index, src in enumerate(MONITORED_HOSTS):
            # Each host starts at its own offset so the collector is not hit in lockstep.
            ts = WINDOW_START.timestamp() + host_index * 7.0
            while ts < WINDOW_END.timestamp():
                self.rows.append(
                    (ts, _http_line(ts, src, self.rng.randint(49152, 65535), MONITOR_IP,
                                    8080, "POST", MONITOR_HOST, "/heartbeat", MONITOR_UA,
                                    self.rng.randint(80, 160), self.rng.randint(0, 20),
                                    204))
                )
                total += 1
                ts += interval + self.rng.uniform(-jitter, jitter)
        self.ground_truth["monitor_beacons"] = total

    # -- the C2 beacon ---------------------------------------------------------------

    def beacon(self) -> None:
        """A periodic HTTP beacon: check-in roughly every 60 s with +/-25% jitter, running
        continuously across the window. Most check-ins are small GETs; the server
        occasionally returns a larger body (tasking), and periodically the implant POSTs a
        large body (exfil). Only the victim talks to this external host."""
        interval, jitter = 60.0, 15.0
        ts = WINDOW_START.timestamp() + 7 * 60 + self.rng.uniform(0, 20)
        session = _rand_label(self.rng, HEX, 8)
        seq = 0
        checkins = posts = 0
        exfil_bytes = 0
        first_ts = last_ts = None
        gaps: list[float] = []
        prev = None
        while ts < WINDOW_END.timestamp():
            seq += 1
            if seq % 12 == 0:
                # Exfil: a large outbound POST. This is the volume tell.
                body = self.rng.randint(4000, 60000)
                self.rows.append(
                    (ts, _http_line(ts, VICTIM_IP, self.rng.randint(49152, 65535), C2_IP, 80,
                                    "POST", C2_DOMAIN, f"/cm/upload?s={session}&n={seq}",
                                    C2_USER_AGENT, body, self.rng.randint(0, 30), 200,
                                    "application/octet-stream"))
                )
                posts += 1
                exfil_bytes += body
            else:
                # Check-in: tiny GET, usually an empty/small answer, occasionally tasking.
                tasking = self.rng.random() < 0.12
                resp = self.rng.randint(300, 1800) if tasking else self.rng.randint(0, 48)
                self.rows.append(
                    (ts, _http_line(ts, VICTIM_IP, self.rng.randint(49152, 65535), C2_IP, 80,
                                    "GET", C2_DOMAIN, f"/cm/collect?s={session}&q={seq:04x}",
                                    C2_USER_AGENT, 0, resp, 200 if resp else 204,
                                    "application/octet-stream" if resp else "-"))
                )
                checkins += 1
            if prev is not None:
                gaps.append(ts - prev)
            prev = ts
            first_ts = first_ts or ts
            last_ts = ts
            ts += interval + self.rng.uniform(-jitter, jitter)

        gaps.sort()
        self.ground_truth.update(
            {
                "beacon_checkins": checkins,
                "beacon_posts": posts,
                "beacon_total": checkins + posts,
                "beacon_exfil_bytes": exfil_bytes,
                "beacon_median_gap_s": round(gaps[len(gaps) // 2], 1) if gaps else 0,
                "beacon_min_gap_s": round(gaps[0], 1) if gaps else 0,
                "beacon_max_gap_s": round(gaps[-1], 1) if gaps else 0,
                "beacon_first_seen": datetime.fromtimestamp(first_ts, timezone.utc).isoformat(),
                "beacon_last_seen": datetime.fromtimestamp(last_ts, timezone.utc).isoformat(),
            }
        )

    def render(self) -> str:
        self.rows.sort(key=lambda row: row[0])
        header = "\n".join(
            [
                "#separator \\x09",
                "#set_separator\t,",
                "#empty_field\t(empty)",
                "#unset_field\t-",
                "#path\thttp",
                f"#open\t{WINDOW_START.strftime('%Y-%m-%d-%H-%M-%S')}",
                "#fields\t" + "\t".join(_HTTP_FIELDS),
                "#types\t" + "\t".join(_HTTP_TYPES),
            ]
        )
        return header + "\n" + "\n".join(row[1] for row in self.rows) + "\n"


def dhcp_log() -> str:
    """Lease records so the IP-to-host mapping the alert relies on has a primary source.
    The victim's ACK is line 4 and its RENEW is line 8, so a brief that identifies the
    host has specific lines to cite."""
    rows = [
        "2026-09-04 06:58:03 ACK 10.12.34.11 00:1b:44:11:3a:b7 wks-4410 lease=28800",
        "2026-09-04 07:11:27 ACK 10.12.34.14 00:1b:44:11:3a:c1 wks-4414 lease=28800",
        "2026-09-04 07:29:52 ACK 10.12.34.40 3c:22:fb:80:12:9e mbp-4440 lease=28800",
        f"2026-09-04 07:41:15 ACK {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
        "2026-09-04 07:55:48 ACK 10.12.34.5 00:25:90:aa:31:7d collector-01 lease=86400",
        "2026-09-04 08:02:33 ACK 10.12.34.22 00:1b:44:11:52:08 wks-4422 lease=28800",
        "2026-09-04 08:18:19 ACK 10.12.34.51 00:1b:44:11:52:31 wks-4451 lease=28800",
        f"2026-09-04 12:41:15 RENEW {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
    ]
    return "\n".join(rows) + "\n"


def alert_json() -> dict:
    return {
        "alert_id": "CORELIGHT-2026-09-04-0044190",
        "detector": "corelight-ndr",
        "rule_name": "ANOMALY Possible HTTP Beaconing to Rare External Host",
        "status": "open",
        "severity": "high",
        "first_seen": "2026-09-04T13:22:07Z",
        "last_seen": "2026-09-04T15:58:41Z",
        "summary": (
            "Behavioural analytics flagged host 10.12.34.72 for periodic HTTP connections "
            "to cdn-metric-collector.net (185.243.115.94), a destination seen from no other "
            "host and newly observed on this network. The detector scores connection "
            "regularity and destination rarity; it does not inspect User-Agent strings or "
            "request bodies."
        ),
        "entities": [
            {"kind": "ip", "value": VICTIM_IP, "note": "source host of the periodic connections"},
            {"kind": "domain", "value": C2_DOMAIN, "note": "rare external destination"},
        ],
        "raw_detector_fields": {
            "sensor": "corelight-eth0-01",
            "model": "beaconing-v3",
            "regularity_score": "0.94",
            "destination_prevalence": "1 host",
            "category": "Command and Control",
            "highest_priority": "1",
        },
    }


def ground_truth_md(stats: dict) -> str:
    return f"""# Ground truth — cases/http-c2

Generated by `scripts/make_http_c2_case.py` (seed {SEED}). This file sits at the case
root, **not** in `logs/`, so `analyze.py` never reads it. Use it to grade the brief.

## What actually happened

An HTTP beacon from **{VICTIM_HOST} / {VICTIM_IP}** (user {VICTIM_USER}) to
**{C2_DOMAIN}** at **{C2_IP}**, a rare external host contacted by no one else.

- **{stats['beacon_total']} beacon transactions** ({stats['beacon_checkins']} GET
  check-ins + {stats['beacon_posts']} POST uploads), first at
  `{stats['beacon_first_seen']}`, last at `{stats['beacon_last_seen']}`.
- **Periodic, not bursty.** Inter-event gaps: min {stats['beacon_min_gap_s']} s,
  median {stats['beacon_median_gap_s']} s, max {stats['beacon_max_gap_s']} s — a ~60 s
  interval with jitter, continuous across the window. A brief that describes this as
  "bursty sessions" has mis-read it; the `timeline` skill should report no idle gap
  exceeding the burst factor (i.e. steady).
- **Anomalous User-Agent.** Every beacon request carries the identical hardcoded string
  `{C2_USER_AGENT}` — an ancient IE/Trident agent, out of place on an estate that
  otherwise sends current Chrome/Edge/Firefox. It is constant across every request.
- **Outbound exfil.** {stats['beacon_posts']} POSTs to `/cm/upload` carry large request
  bodies totalling **{stats['beacon_exfil_bytes']:,} bytes** outbound. Check-in GETs are
  tiny; the volume is in the *request* direction, the signature of exfiltration rather
  than a download.

## The decoys — all benign, all beacon-shaped

A brief that flags any of these as the intrusion is producing false positives:

1. **Internal monitoring agent** ({stats['monitor_beacons']} heartbeats) — POSTs to
   `{MONITOR_HOST}` ({MONITOR_IP}) every ~120 s from {len(MONITORED_HOSTS)} hosts,
   **including the victim**. Fixed interval, single destination, POST method: beacon-shaped
   by every crude test. Benign — internal collector, tiny bodies, honest `corp-monitor`
   User-Agent. This is the decoy that proves periodicity alone is not evidence.
2. **OCSP checks** — periodic GETs to `ocsp.digicert.com`, `Microsoft-CryptoAPI` agent.
3. **Windows telemetry** — scheduled POSTs to `v10.events.data.microsoft.com`.
4. **Update poller** — BITS range GETs from `ctldl.windowsupdate.com` with large
   *inbound* download bodies — the mirror image of the C2's outbound uploads, there to
   catch a brief that keys on "large HTTP bodies" without checking direction.

## Grading the brief

A good brief should:

- attribute the beaconing to {VICTIM_IP}, and to {VICTIM_HOST} via `dhcp.log`;
- name the C2 destination ({C2_DOMAIN} / {C2_IP}) and note it is a rare, single-source
  external host;
- describe the timing as **periodic/regular beaconing with jitter**, not bursts;
- flag the anomalous, constant User-Agent;
- note the outbound POST volume (exfiltration direction), not just "large transfers";
- **not** flag the four decoys — especially the internal monitoring heartbeat — or if it
  mentions them, explicitly distinguish them;
- record what it could not determine — there is no process/endpoint telemetry here, so
  attribution to a binary is not possible from this data.

## Volumes

| | lines |
|---|---|
| total HTTP records | {stats['total_http']} |
| C2 beacon | {stats['beacon_total']} |
| monitoring heartbeats | {stats['monitor_beacons']} |
| other decoys | {stats['decoy_other']} |
| ordinary browsing | {stats['benign']} |
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="cases/http-c2")
    parser.add_argument("--target-mb", type=float, default=1.2)
    args = parser.parse_args()

    rng = random.Random(SEED)
    gen = Generator(rng)

    gen.beacon()
    gen.decoy_monitoring(interval=120.0, jitter=4.0)
    other = {"ocsp": 240, "telemetry": 200, "update": 90}
    gen.decoy_ocsp(other["ocsp"])
    gen.decoy_telemetry(other["telemetry"])
    gen.decoy_update_poller(other["update"])
    planted = len(gen.rows)

    target_bytes = int(args.target_mb * 1_000_000)
    gen.benign_browsing(300)
    for _ in range(3):
        size = len(gen.render())
        if size >= target_bytes:
            break
        sample = "\n".join(row[1] for row in gen.rows[-300:])
        per_line = len(sample) / 300
        gen.benign_browsing(max(1, int((target_bytes - size) / per_line)))

    out = Path(args.out)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    http_text = gen.render()
    (out / "logs" / "http.log").write_text(http_text, encoding="utf-8")
    (out / "logs" / "dhcp.log").write_text(dhcp_log(), encoding="utf-8")
    (out / "alert.json").write_text(json.dumps(alert_json(), indent=2) + "\n", encoding="utf-8")

    stats = {
        **gen.ground_truth,
        "decoy_other": sum(other.values()),
        "benign": len(gen.rows) - planted,
        "total_http": len(gen.rows),
    }
    (out / "GROUND_TRUTH.md").write_text(ground_truth_md(stats), encoding="utf-8")

    size_mb = len(http_text) / 1_000_000
    print(f"wrote {out}/")
    print(f"  logs/http.log   {len(gen.rows)} records, {size_mb:.2f} MB")
    print(f"  logs/dhcp.log   8 leases")
    print(f"  alert.json      corelight-ndr beaconing")
    print(f"  GROUND_TRUTH.md not read by analyze.py")
    print(f"  beacon: {stats['beacon_total']} txns ({stats['beacon_posts']} POST exfil), "
          f"median gap {stats['beacon_median_gap_s']}s; "
          f"monitor decoy: {stats['monitor_beacons']} heartbeats")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
