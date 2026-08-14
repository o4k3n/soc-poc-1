#!/usr/bin/env python3
"""Generate a synthetic DNS-tunnelling case: cases/dns-tunnel/.

Single-purpose and seeded, so the dataset is reproducible and reviewable rather than a
blob of committed noise. Regenerate with:

    python3 scripts/make_dns_tunnel_case.py [--out cases/dns-tunnel] [--target-mb 1.0]

What is planted, and why it is planted that way:

  * A dnscat2-style tunnel from ONE workstation to ONE registered domain. Hex-encoded
    labels, TXT and CNAME queries, and answers that **succeed and carry payload**. That
    last part matters: the existing beacon fixture NXDOMAINs throughout, which is a dead
    C2. A working tunnel resolves, and the returning TXT records are the exfiltration
    channel. An investigation that only looks for failures will miss it.
  * Session bursts separated by idle gaps, not a metronome. Real tunnels are bursty
    because they carry actual traffic; perfectly regular intervals are a beacon, not a
    tunnel, and conflating the two is a mistake worth being able to catch.
  * **Benign decoys that defeat the obvious heuristic.** "Long high-entropy subdomain =
    tunnel" is wrong, and the dataset proves it: DNSBL lookups embed reversed IPs, AV
    reputation services embed file hashes, CDN cache keys embed content hashes, and DKIM
    selectors are TXT lookups by design. All four are legitimate and all four look
    superficially like the tunnel. A brief that flags them is producing false positives.

GROUND_TRUTH.md is written to the case root, NOT into logs/, so the runner never reads
it -- discover_case only looks at alert.json and logs/. It is there to grade the brief
against afterwards.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260814

# --- the scenario -------------------------------------------------------------------
TUNNEL_DOMAIN = "api-sync-telemetry.net"
TUNNEL_NS = "45.77.203.118"
VICTIM_IP = "10.12.34.56"
VICTIM_HOST = "wks-2291"
VICTIM_MAC = "00:1b:44:11:7f:2a"
VICTIM_USER = "d.novak"
RESOLVER = "10.12.2.5"

WINDOW_START = datetime(2026, 8, 14, 8, 0, 0, tzinfo=timezone.utc)
WINDOW_END = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

# Ordinary estate hosts generating background noise.
BENIGN_HOSTS = [f"10.12.34.{n}" for n in (11, 14, 18, 22, 27, 31, 40, 44, 51, 63, 70, 88)]

BENIGN_DOMAINS = [
    "outlook.office365.com", "teams.microsoft.com", "login.microsoftonline.com",
    "www.google.com", "fonts.gstatic.com", "update.corp.example.com",
    "intranet.corp.example.com", "git.corp.example.com", "jira.corp.example.com",
    "packages.debian.org", "registry.npmjs.org", "pypi.org", "api.github.com",
    "slack.com", "zoom.us", "cdn.jsdelivr.net", "ocsp.digicert.com",
    "crl.microsoft.com", "time.windows.com", "ntp.corp.example.com",
    "mail.corp.example.com", "printsrv.corp.example.com", "vpn.corp.example.com",
    "sharepoint.corp.example.com", "docs.corp.example.com",
]

RRTYPES_BENIGN = ["A"] * 14 + ["AAAA"] * 4 + ["CNAME"] * 2 + ["TXT", "MX", "PTR", "SRV"]

HEX = "0123456789abcdef"
B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _rand_label(rng: random.Random, alphabet: str, length: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def _zeek_line(
    ts: float, src: str, sport: int, query: str, qtype: str, rcode: str, answers: list[str],
    trans_id: int, rtt: float,
) -> str:
    """Zeek dns.log, tab-separated, in field order.

    Chosen over Suricata EVE JSON for the bulk because JSON keys cost ~30% more tokens
    per line, and every token spent on repeating `"event_type":"dns"` is a line of data
    the sweep cannot afford to read.
    """
    qtype_num = {"A": "1", "NS": "2", "CNAME": "5", "PTR": "12", "MX": "15",
                 "TXT": "16", "AAAA": "28", "SRV": "33", "NULL": "10"}[qtype]
    rcode_num = {"NOERROR": "0", "FORMERR": "1", "SERVFAIL": "2", "NXDOMAIN": "3"}[rcode]
    return "\t".join(
        [
            f"{ts:.6f}", f"C{_uid(ts, sport)}", src, str(sport), RESOLVER, "53", "udp",
            str(trans_id), f"{rtt:.6f}", query, "1", "C_INTERNET", qtype_num, qtype,
            rcode_num, rcode, "F", "F", "T", "T", "0",
            ",".join(answers) if answers else "-",
            ",".join("60" for _ in answers) if answers else "-",
            "F",
        ]
    )


def _uid(ts: float, port: int) -> str:
    raw = f"{int(ts * 1e6)}{port}"
    return "".join(B32[int(c) % 32] for c in raw[-12:])


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
            domain = self.rng.choice(BENIGN_DOMAINS)
            qtype = self.rng.choice(RRTYPES_BENIGN)
            if self.rng.random() < 0.04:
                rcode, answers = "NXDOMAIN", []
            else:
                rcode = "NOERROR"
                answers = [f"{self.rng.randint(20, 210)}.{self.rng.randint(0,255)}."
                           f"{self.rng.randint(0,255)}.{self.rng.randint(1,254)}"]
            self.rows.append(
                (ts, _zeek_line(ts, src, self.rng.randint(49152, 65535), domain, qtype,
                                rcode, answers, self.rng.randint(1, 65535),
                                self.rng.uniform(0.001, 0.09)))
            )

    # -- decoys: benign, and shaped like the tunnel -----------------------------------

    def decoy_dnsbl(self, count: int) -> None:
        """Reversed-IP lookups against a blocklist. Long numeric labels, huge volume,
        one source host -- the mail gateway. Textbook false positive."""
        gateway = "10.12.34.9"
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            octets = [str(self.rng.randint(1, 254)) for _ in range(4)]
            query = f"{'.'.join(reversed(octets))}.zen.spamhaus.example.org"
            hit = self.rng.random() < 0.15
            self.rows.append(
                (ts, _zeek_line(ts, gateway, self.rng.randint(49152, 65535), query, "A",
                                "NOERROR" if hit else "NXDOMAIN",
                                ["127.0.0.2"] if hit else [], self.rng.randint(1, 65535),
                                self.rng.uniform(0.01, 0.2)))
            )

    def decoy_av_reputation(self, count: int) -> None:
        """File-hash reputation lookups: 40-char hex labels, exactly the shape of an
        encoded tunnel label, from many hosts running the same agent."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            query = f"{_rand_label(self.rng, HEX, 40)}.avts.vendor-cloud.example.net"
            self.rows.append(
                (ts, _zeek_line(ts, src, self.rng.randint(49152, 65535), query, "TXT",
                                "NOERROR", [f"v=1;score={self.rng.randint(0, 99)}"],
                                self.rng.randint(1, 65535), self.rng.uniform(0.02, 0.15)))
            )

    def decoy_cdn_cache_keys(self, count: int) -> None:
        """Content-hash hostnames from a CDN. High entropy, high volume, benign."""
        span = (WINDOW_END - WINDOW_START).total_seconds()
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            src = self.rng.choice(BENIGN_HOSTS)
            query = f"{_rand_label(self.rng, B32, 26)}.cache.cdn-assets.example.com"
            self.rows.append(
                (ts, _zeek_line(ts, src, self.rng.randint(49152, 65535), query, "A",
                                "NOERROR", [f"151.101.{self.rng.randint(0,64)}.{self.rng.randint(1,254)}"],
                                self.rng.randint(1, 65535), self.rng.uniform(0.005, 0.05)))
            )

    def decoy_dkim(self, count: int) -> None:
        """DKIM selector lookups: TXT queries returning long base64 payloads. The
        tunnel's answer shape, entirely legitimately."""
        gateway = "10.12.34.9"
        span = (WINDOW_END - WINDOW_START).total_seconds()
        partners = ["partner-a.example.com", "partner-b.example.org", "supplier.example.net"]
        for _ in range(count):
            ts = WINDOW_START.timestamp() + self.rng.uniform(0, span)
            query = f"{self.rng.choice(['s1', 's2', 'selector1', 'google'])}._domainkey." \
                    f"{self.rng.choice(partners)}"
            payload = f"v=DKIM1; k=rsa; p={_rand_label(self.rng, B32, 60)}"
            self.rows.append(
                (ts, _zeek_line(ts, gateway, self.rng.randint(49152, 65535), query, "TXT",
                                "NOERROR", [payload], self.rng.randint(1, 65535),
                                self.rng.uniform(0.02, 0.3)))
            )

    # -- the tunnel -------------------------------------------------------------------

    def tunnel(self) -> None:
        """Bursty sessions of encoded queries with successful, payload-bearing answers."""
        sessions = [
            (datetime(2026, 8, 14, 8, 47, 12, tzinfo=timezone.utc), 96),
            (datetime(2026, 8, 14, 9, 31, 40, tzinfo=timezone.utc), 210),
            (datetime(2026, 8, 14, 10, 12, 3, tzinfo=timezone.utc), 64),
            (datetime(2026, 8, 14, 10, 58, 27, tzinfo=timezone.utc), 288),
            (datetime(2026, 8, 14, 11, 39, 55, tzinfo=timezone.utc), 130),
        ]
        first_ts = None
        last_ts = None
        total = 0
        # The handshake: the client resolves the NS record first, which is the line that
        # ties the domain to attacker infrastructure.
        ns_ts = sessions[0][0].timestamp() - 3.2
        self.rows.append(
            (ns_ts, _zeek_line(ns_ts, VICTIM_IP, 51402, TUNNEL_DOMAIN, "NS", "NOERROR",
                               [f"ns1.{TUNNEL_DOMAIN}"], 40001, 0.184))
        )
        self.rows.append(
            (ns_ts + 0.2, _zeek_line(ns_ts + 0.2, VICTIM_IP, 51402, f"ns1.{TUNNEL_DOMAIN}",
                                     "A", "NOERROR", [TUNNEL_NS], 40002, 0.171))
        )

        for start, count in sessions:
            ts = start.timestamp()
            for index in range(count):
                # Bursty: sub-second within a session, with occasional stalls. Not a
                # metronome -- this is carrying data, not announcing itself.
                ts += self.rng.choice([0.18, 0.24, 0.31, 0.42, 0.9, 1.4, 3.1])
                qtype = "TXT" if self.rng.random() < 0.82 else "CNAME"
                # dnscat2-ish: hex payload chunk, session id, sequence.
                label = _rand_label(self.rng, HEX, self.rng.choice([28, 32, 36, 40]))
                query = f"{label}.{_rand_label(self.rng, HEX, 4)}.t.{TUNNEL_DOMAIN}"
                if qtype == "TXT":
                    answers = [_rand_label(self.rng, B32, self.rng.choice([48, 64, 96]))]
                else:
                    answers = [f"{_rand_label(self.rng, HEX, 24)}.r.{TUNNEL_DOMAIN}"]
                self.rows.append(
                    (ts, _zeek_line(ts, VICTIM_IP, self.rng.randint(49152, 65535), query,
                                    qtype, "NOERROR", answers, self.rng.randint(1, 65535),
                                    self.rng.uniform(0.12, 0.31)))
                )
                first_ts = first_ts or ts
                last_ts = ts
                total += 1

        self.ground_truth["tunnel_queries"] = total
        self.ground_truth["tunnel_first_seen"] = datetime.fromtimestamp(
            first_ts, timezone.utc
        ).isoformat()
        self.ground_truth["tunnel_last_seen"] = datetime.fromtimestamp(
            last_ts, timezone.utc
        ).isoformat()
        self.ground_truth["tunnel_sessions"] = len(sessions)

    def render(self) -> str:
        self.rows.sort(key=lambda row: row[0])
        header = "\n".join(
            [
                "#separator \\x09",
                "#set_separator\t,",
                "#empty_field\t(empty)",
                "#unset_field\t-",
                "#path\tdns",
                f"#open\t{WINDOW_START.strftime('%Y-%m-%d-%H-%M-%S')}",
                "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id"
                "\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\trcode\trcode_name"
                "\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected",
                "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\tinterval\tstring"
                "\tcount\tstring\tcount\tstring\tcount\tstring\tbool\tbool\tbool\tbool\tcount"
                "\tvector[string]\tvector[interval]\tbool",
            ]
        )
        return header + "\n" + "\n".join(row[1] for row in self.rows) + "\n"


def suricata_alerts() -> str:
    """The EVE alert events Suricata would have written. Small, and the reason the
    alert's own claims are citable rather than asserted."""
    events = []
    for n, (ts, sid, sig, count) in enumerate(
        [
            ("2026-08-14T09:33:41.882014+0000", 2027758,
             "ET DNS Query for Suspicious .net Domain with Excessive Subdomain Entropy", 1),
            ("2026-08-14T10:14:09.114872+0000", 2023883,
             "ET TROJAN Possible DNS Tunneling (High Volume TXT Queries to Single Domain)", 1),
            ("2026-08-14T11:02:55.400291+0000", 2023883,
             "ET TROJAN Possible DNS Tunneling (High Volume TXT Queries to Single Domain)", 1),
            ("2026-08-14T11:41:18.774650+0000", 2027758,
             "ET DNS Query for Suspicious .net Domain with Excessive Subdomain Entropy", 1),
        ],
        start=1,
    ):
        events.append(
            json.dumps(
                {
                    "timestamp": ts,
                    "flow_id": 1874392017483920 + n,
                    "in_iface": "eth0",
                    "event_type": "alert",
                    "src_ip": VICTIM_IP,
                    "src_port": 51402 + n,
                    "dest_ip": RESOLVER,
                    "dest_port": 53,
                    "proto": "UDP",
                    "alert": {
                        "action": "allowed",
                        "gid": 1,
                        "signature_id": sid,
                        "rev": 4,
                        "signature": sig,
                        "category": "A Network Trojan was detected",
                        "severity": 1,
                    },
                    "app_proto": "dns",
                    "flow": {"pkts_toserver": 2, "pkts_toclient": 2,
                             "bytes_toserver": 214, "bytes_toclient": 388},
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events) + "\n"


def dhcp_log() -> str:
    """Lease records so the IP-to-host mapping the alert relies on has a primary source."""
    rows = [
        "2026-08-14 07:02:11 ACK 10.12.34.11 00:1b:44:11:3a:b7 wks-2210 lease=28800",
        "2026-08-14 07:14:39 ACK 10.12.34.14 00:1b:44:11:3a:c1 wks-2214 lease=28800",
        "2026-08-14 07:31:02 ACK 10.12.34.18 3c:22:fb:80:12:9e mbp-2218 lease=28800",
        f"2026-08-14 07:44:57 ACK {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
        "2026-08-14 07:52:20 ACK 10.12.34.9 00:25:90:aa:31:7d mailgw-01 lease=86400",
        "2026-08-14 08:03:44 ACK 10.12.34.22 00:1b:44:11:52:08 wks-2222 lease=28800",
        "2026-08-14 08:19:05 ACK 10.12.34.27 00:1b:44:11:52:31 wks-2227 lease=28800",
        f"2026-08-14 11:44:57 RENEW {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
    ]
    return "\n".join(rows) + "\n"


def alert_json() -> dict:
    return {
        "alert_id": "SURICATA-2026-08-14-0098431",
        "detector": "suricata",
        "rule_name": "ET TROJAN Possible DNS Tunneling (High Volume TXT Queries to Single Domain)",
        "status": "open",
        "severity": "high",
        "first_seen": "2026-08-14T09:33:41Z",
        "last_seen": "2026-08-14T11:41:18Z",
        "summary": (
            "Sensor eth0 raised 4 signature hits for host 10.12.34.56 over a two-hour "
            "window: sustained TXT queries to subdomains of api-sync-telemetry.net with "
            "high label entropy. The signature fires on query volume to a single "
            "second-level domain and does not itself inspect responses."
        ),
        "entities": [
            {"kind": "ip", "value": VICTIM_IP, "note": "source host of the flagged queries"},
            {"kind": "domain", "value": TUNNEL_DOMAIN, "note": "queried second-level domain"},
        ],
        "raw_detector_fields": {
            "sensor": "suricata-eth0-01",
            "suricata_version": "7.0.5",
            "ruleset": "emerging-threats 2026-08-12",
            "signature_ids": "2023883, 2027758",
            "hits": "4",
            "highest_priority": "1",
            "category": "A Network Trojan was detected",
        },
    }


def ground_truth_md(stats: dict) -> str:
    return f"""# Ground truth — cases/dns-tunnel

Generated by `scripts/make_dns_tunnel_case.py` (seed {SEED}). This file sits at the case
root, **not** in `logs/`, so `analyze.py` never reads it. Use it to grade the brief.

## What actually happened

A DNS tunnel from **{VICTIM_HOST} / {VICTIM_IP}** (user {VICTIM_USER}) to
**{TUNNEL_DOMAIN}**, delegated to nameserver **{TUNNEL_NS}**.

- **{stats['tunnel_queries']} tunnel queries** across **{stats['tunnel_sessions']} bursty
  sessions**, first at `{stats['tunnel_first_seen']}`, last at `{stats['tunnel_last_seen']}`.
- Hex-encoded labels (28–40 chars) under `t.{TUNNEL_DOMAIN}`, ~82% TXT and ~18% CNAME.
- **Answers succeed and carry payload.** Every tunnel query returns NOERROR with a
  base32 TXT record. This is the exfiltration channel, and it is the detail that
  separates a live tunnel from a dead beacon.
- Two setup lines precede the first session: an `NS` query for the domain and an `A`
  query for `ns1.{TUNNEL_DOMAIN}` resolving to {TUNNEL_NS}. These tie the domain to
  attacker infrastructure and are the strongest single pieces of evidence in the case.
- Timing is **bursty, not periodic** — sub-second within a session, long idle gaps
  between. A brief that describes this as "regular-interval beaconing" has mis-read it.

## The decoys — all benign, all tunnel-shaped

A brief that flags any of these is producing false positives:

1. **DNSBL lookups** ({stats['decoy_dnsbl']} queries) from the mail gateway 10.12.34.9 —
   reversed-IP labels against `zen.spamhaus.example.org`. High volume, one source, long
   numeric labels, mostly NXDOMAIN.
2. **AV reputation lookups** ({stats['decoy_av']} queries) — 40-character hex labels
   under `avts.vendor-cloud.example.net`, TXT type, from many hosts. Character-for-character
   the same shape as a tunnel label.
3. **CDN cache keys** ({stats['decoy_cdn']} queries) — 26-character base32 hostnames under
   `cache.cdn-assets.example.com`. High entropy, high volume.
4. **DKIM selector lookups** ({stats['decoy_dkim']} queries) from the mail gateway — TXT
   queries returning long base64 payloads, which is the tunnel's *answer* shape.

## Grading the brief

A good brief should:

- attribute the traffic to {VICTIM_IP}, and to {VICTIM_HOST} via `dhcp.log`;
- cite the NS/A delegation lines, not only the query volume;
- note that the answers succeeded and carried data;
- describe the timing as bursty sessions rather than a fixed interval;
- **not** flag the four decoys, or if it mentions them, explicitly distinguish them;
- record what it could not determine — there is no process-level telemetry in this case,
  so attribution to a binary is not possible from this data.

## Volumes

| | lines |
|---|---|
| total DNS records | {stats['total_dns']} |
| tunnel | {stats['tunnel_queries']} |
| decoys | {stats['decoy_total']} |
| ordinary background | {stats['benign']} |
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="cases/dns-tunnel")
    parser.add_argument("--target-mb", type=float, default=1.0)
    args = parser.parse_args()

    rng = random.Random(SEED)
    gen = Generator(rng)

    # Decoy and tunnel volumes are fixed; background fills the rest of the budget.
    decoys = {"dnsbl": 420, "av": 260, "cdn": 340, "dkim": 90}
    gen.tunnel()
    stats_planted = len(gen.rows) + sum(decoys.values())
    gen.decoy_dnsbl(decoys["dnsbl"])
    gen.decoy_av_reputation(decoys["av"])
    gen.decoy_cdn_cache_keys(decoys["cdn"])
    gen.decoy_dkim(decoys["dkim"])

    # Fill to the size target with ordinary traffic, measured rather than guessed. Two
    # passes: tunnel and decoy lines are longer than benign ones, so a single estimate
    # taken over the mixed set overshoots bytes-per-line and undershoots the fill.
    target_bytes = int(args.target_mb * 1_000_000)
    gen.benign_traffic(200)
    for _ in range(3):
        size = len(gen.render())
        if size >= target_bytes:
            break
        benign_sample = "\n".join(row[1] for row in gen.rows[-200:])
        per_benign_line = len(benign_sample) / 200
        gen.benign_traffic(max(1, int((target_bytes - size) / per_benign_line)))

    out = Path(args.out)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    dns_text = gen.render()
    (out / "logs" / "dns.log").write_text(dns_text, encoding="utf-8")
    (out / "logs" / "suricata_eve_alert.json").write_text(suricata_alerts(), encoding="utf-8")
    (out / "logs" / "dhcp.log").write_text(dhcp_log(), encoding="utf-8")
    (out / "alert.json").write_text(json.dumps(alert_json(), indent=2) + "\n", encoding="utf-8")

    stats = {
        **gen.ground_truth,
        "decoy_dnsbl": decoys["dnsbl"],
        "decoy_av": decoys["av"],
        "decoy_cdn": decoys["cdn"],
        "decoy_dkim": decoys["dkim"],
        "decoy_total": sum(decoys.values()),
        "benign": len(gen.rows) - stats_planted,
        "total_dns": len(gen.rows),
    }
    (out / "GROUND_TRUTH.md").write_text(ground_truth_md(stats), encoding="utf-8")

    size_mb = len(dns_text) / 1_000_000
    print(f"wrote {out}/")
    print(f"  logs/dns.log                 {len(gen.rows)} records, {size_mb:.2f} MB")
    print(f"  logs/suricata_eve_alert.json 4 alert events")
    print(f"  logs/dhcp.log                8 leases")
    print(f"  alert.json                   suricata, sid 2023883")
    print(f"  GROUND_TRUTH.md              not read by analyze.py")
    print(f"  tunnel: {stats['tunnel_queries']} queries, decoys: {stats['decoy_total']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
