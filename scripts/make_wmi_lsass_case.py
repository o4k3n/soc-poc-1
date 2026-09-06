#!/usr/bin/env python3
"""Generate cases/wmi-lsass: WMI lateral movement into an LSASS credential dump.

Windows host telemetry, not network logs -- the third case, and the first on Windows
event data. Two real attack samples from the public EVTX-ATTACK-SAMPLES corpus
(sbousseaden, GPL-3.0) are parsed, every identifier in them is replaced by a fresh
seeded one, and the events are rebased into a synthetic estate of benign Security and
Sysmon activity with four decoys, each shaped like one piece of the attack:

  Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx     4624 type-3 logon, 4688 WmiPrvSE
  Credential Access/sysmon_10_..._logonpasswords.evtx   Sysmon 10, lsass access 0x1010

Only the *technique* is public; nothing here can be matched to a memorised sample,
because host names, accounts, SIDs, logon ids, IPs, GUIDs and timestamps are all novel
and seeded. The chain the investigation must reconstruct:

  a type-3 (network) logon to the victim as a privileged account, from another
  workstation's IP  ->  WmiPrvSE.exe (the WMI provider, running as SYSTEM) spawns cmd.exe
  ->  cmd invokes the comsvcs.dll MiniDump LOLBin  ->  a process reads lsass.exe with
  GrantedAccess 0x1010.

The alert fires only on the shallow tip -- "cmd.exe spawned by WmiPrvSE.exe on the
victim" -- and explicitly does not look at the logon that authorised it, the account,
the source host, or the process-access events. Everything the brief must add is a pivot
away from that one line.

The logs are JSON lines (one event object per line), which is what the field= selector
reads on a .jsonl file. Keys are ordered so ts/event_id/computer lead and the long
discriminators (CommandLine, GrantedAccess, CallTrace) trail, where the ledger's
elision keeps them visible.

Usage:
    python3 scripts/make_wmi_lsass_case.py [--out cases/wmi-lsass]
                                           [--evtx-dir cases/_evtx] [--target-mb 1.4]
GROUND_TRUTH.md is written to the case root, NOT into logs/, so analyze.py never reads it.
"""
from __future__ import annotations

import argparse
import json
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

SEED = 20260907

# -- the estate ------------------------------------------------------------------------
DOMAIN = "CORP"
VICTIM_HOST = "WKS-3355"
VICTIM_IP = "10.12.34.55"
VICTIM_MAC = "00:1b:44:11:6d:2a"
# The account the attacker authenticated as: a deployment service account that has no
# business driving an interactive WMI command. Privileged (a local admin), which is why
# the logon and the credential theft both succeed.
ATTACK_USER = "svc_deploy"
ATTACK_USER_SID = "S-1-5-21-341049218-2894104772-1560093651-1142"
# Where the type-3 logon came from: another workstation in the same subnet, itself
# attributable via dhcp.log -- a second host to name, unlike the network cases.
SOURCE_HOST = "WKS-2208"
SOURCE_IP = "10.12.34.71"
SOURCE_MAC = "00:1b:44:11:59:14"
# The credential-dump LOLBin the payload runs (comsvcs.dll MiniDump of lsass), the pid it
# targets and the temp file it writes.
DUMP_PID = 704
DUMP_FILE = r"C:\Windows\Temp\wct5A2B.tmp"
DUMPER_IMAGE = r"C:\Windows\System32\rundll32.exe"
ATTACK_GRANTED = "0x1010"  # read + query info: the mask a dumper needs, the sample's value

# Decoy infrastructure.
MGMT_HOST = "SRV-SCCM01"          # management server that legitimately runs WMI everywhere
MGMT_IP = "10.12.34.8"
MGMT_USER = "svc_sccm"
AV_IMAGE = r"C:\Program Files\Windows Defender\MsMpEng.exe"
JUMP_HOST = "SRV-JUMP01"          # admin RDP origin
JUMP_IP = "10.12.34.9"
FILESRV_IP = "10.12.34.10"        # backup service, high-volume type-3 logons

# Ordinary users and their workstations for background.
USERS = ["a.lindqvist", "m.okafor", "s.haldorsen", "t.almeida", "p.novak", "j.chen",
         "r.delgado", "k.andersson"]
HOSTS = [("WKS-3301", "10.12.34.31"), ("WKS-3312", "10.12.34.32"),
         ("WKS-3324", "10.12.34.33"), ("WKS-3340", "10.12.34.40"),
         ("WKS-3351", "10.12.34.51"), (VICTIM_HOST, VICTIM_IP)]
DC_HOST = "SRV-DC01"

# Benign process images that fill 4688 / Sysmon 1.
BENIGN_IMAGES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
    r"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\SearchIndexer.exe",
    r"C:\Windows\System32\backgroundTaskHost.exe",
    r"C:\Program Files\Git\bin\git.exe",
]
# Benign processes that legitimately open lsass, with the masks they use.
BENIGN_LSASS_READERS = [
    (r"C:\Program Files\Windows Defender\MsMpEng.exe", "0x1000"),
    (r"C:\Windows\System32\wininit.exe", "0x1400"),
    (r"C:\Windows\System32\csrss.exe", "0x1400"),
    (r"C:\Windows\System32\svchost.exe", "0x1010"),  # a rare legit 0x1010: forces the
]                                                     # brief onto SourceImage, not the mask

WINDOW_START = datetime(2026, 9, 7, 8, 0, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(hours=3)
SPAN_S = (WINDOW_END - WINDOW_START).total_seconds()
ATTACK_AT = WINDOW_START + timedelta(hours=2, minutes=31)  # one short chain, mid-window

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


# -- EVTX parsing ----------------------------------------------------------------------
def parse_evtx(path: Path) -> list[dict]:
    """Every record of one .evtx as a flat dict: System fields plus each EventData Data
    by its Name. Values of '-' or '' are dropped. Requires python-evtx (extras: cases)."""
    import Evtx.Evtx as evtx  # imported here so the module loads without the extra

    events: list[dict] = []
    with evtx.Evtx(str(path)) as log:
        for record in log.records():
            root = ET.fromstring(record.xml())
            system = root.find("e:System", _NS)
            provider = system.find("e:Provider", _NS)
            event: dict = {
                "event_id": int(system.findtext("e:EventID", default="0", namespaces=_NS)),
                "ts": system.find("e:TimeCreated", _NS).get("SystemTime"),
                "computer": system.findtext("e:Computer", namespaces=_NS),
                "channel": system.findtext("e:Channel", namespaces=_NS),
                "provider": provider.get("Name") if provider is not None else "",
            }
            data = root.find("e:EventData", _NS)
            if data is not None:
                for d in data.findall("e:Data", _NS):
                    name, value = d.get("Name"), (d.text or "").strip()
                    if name and value and value != "-":
                        event[name] = value
            events.append(event)
    return events


def _iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"


class Generator:
    """Builds the two JSON-lines channels. Rows are (epoch, channel, object); render
    sorts one channel by time and serialises it, keys in insertion order."""

    def __init__(self, rng: random.Random, evtx_dir: Path) -> None:
        self.rng = rng
        self.evtx_dir = evtx_dir
        self.rows: list[tuple[float, str, dict]] = []
        self.ground_truth: dict[str, object] = {}

    # -- emit ---------------------------------------------------------------------------
    def _emit(self, ts: datetime, channel: str, obj: dict) -> None:
        self.rows.append((ts.timestamp(), channel, obj))

    def _logon_id(self) -> str:
        return f"0x{self.rng.randint(0x10000, 0xffffff):08x}"

    def _guid(self) -> str:
        return (
            f"{{{self.rng.randint(0, 0xffffffff):08x}-{self.rng.randint(0, 0xffff):04x}-"
            f"{self.rng.randint(0, 0xffff):04x}-{self.rng.randint(0, 0xffff):04x}-"
            f"{self.rng.randint(0, 0xffffffffffff):012x}}}"
        )

    def _pid(self) -> str:
        return f"0x{self.rng.randint(0x400, 0x4fff):04x}"

    # -- Security channel events --------------------------------------------------------
    def _logon(self, ts, computer, user, sid, logon_type, src_ip, src_host,
               logon_id, proc="Kerberos", pkg="Kerberos") -> dict:
        obj = {
            "ts": _iso(ts), "event_id": 4624, "channel": "Security", "computer": computer,
            "provider": "Microsoft-Windows-Security-Auditing",
            "TargetUserName": user, "TargetDomainName": DOMAIN, "TargetUserSid": sid,
            "TargetLogonId": logon_id, "LogonType": logon_type,
            "IpAddress": src_ip, "WorkstationName": src_host,
            "LogonProcessName": proc, "AuthenticationPackageName": pkg,
        }
        self._emit(ts, "security", obj)
        return obj

    def _process(self, ts, computer, user, logon_id, image, parent_image, command_line="") -> dict:
        obj = {
            "ts": _iso(ts), "event_id": 4688, "channel": "Security", "computer": computer,
            "provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": logon_id,
            "NewProcessName": image, "ParentProcessName": parent_image,
            "NewProcessId": self._pid(), "TokenElevationType": "%%1936",
            "CommandLine": command_line,
        }
        self._emit(ts, "security", obj)
        return obj

    def _sysmon_create(self, ts, computer, user, image, parent_image, command_line, logon_id) -> dict:
        obj = {
            "ts": _iso(ts), "event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": computer, "provider": "Microsoft-Windows-Sysmon",
            "User": f"{DOMAIN}\\{user}", "LogonId": logon_id,
            "Image": image, "ParentImage": parent_image,
            "ProcessGuid": self._guid(), "CommandLine": command_line,
        }
        self._emit(ts, "sysmon", obj)
        return obj

    def _sysmon_access(self, ts, computer, source_image, granted, call_trace="") -> dict:
        obj = {
            "ts": _iso(ts), "event_id": 10, "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": computer, "provider": "Microsoft-Windows-Sysmon",
            "SourceImage": source_image, "TargetImage": r"C:\Windows\System32\lsass.exe",
            "SourceProcessGUID": self._guid(), "TargetProcessGUID": self._guid(),
            "GrantedAccess": granted, "CallTrace": call_trace,
        }
        self._emit(ts, "sysmon", obj)
        return obj

    # -- the attack, rebased from the two samples --------------------------------------
    def attack(self) -> None:
        """Parse the two samples, take the events that carry the technique, and rewrite
        every identifier. The chain is placed once, at ATTACK_AT, over ~80 s."""
        lm = parse_evtx(self.evtx_dir / "LM_WMI_4624_4688_TargetHost.evtx")
        sm = parse_evtx(self.evtx_dir / "sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx")

        # From LM: the type-3 admin logon (the sample's Administrator from 10.0.2.17) and
        # the WmiPrvSE 4688. We keep their existence and shapes, not their identifiers.
        sample_logon = next(e for e in lm if e["event_id"] == 4624 and e.get("LogonType") == "3"
                            and e.get("IpAddress", "").count(".") == 3)
        next(e for e in lm if e["event_id"] == 4688
             and e.get("NewProcessName", "").lower().endswith("wmiprvse.exe"))
        sample_access = next(e for e in sm if e["event_id"] == 10)
        self.ground_truth["evtx_source_records"] = (
            f"LM 4624 type {sample_logon['LogonType']} "
            f"proc {sample_logon.get('LogonProcessName')}, LM 4688 WmiPrvSE, "
            f"Sysmon 10 GrantedAccess {sample_access['GrantedAccess']}"
        )

        t = ATTACK_AT
        logon_id = self._logon_id()

        # 1) network logon to the victim as the privileged deploy account, from SOURCE_IP.
        self._logon(t, VICTIM_HOST, ATTACK_USER, ATTACK_USER_SID, "3", SOURCE_IP, SOURCE_HOST,
                    logon_id, proc=sample_logon.get("LogonProcessName", "Kerberos"),
                    pkg=sample_logon.get("AuthenticationPackageName", "Kerberos"))

        # 2) WmiPrvSE.exe, the WMI provider, runs as SYSTEM (the mechanism of remote exec).
        t += timedelta(seconds=self.rng.uniform(1.5, 3.0))
        wmiprvse = r"C:\Windows\System32\wbem\WmiPrvSE.exe"
        self._process(t, VICTIM_HOST, f"{VICTIM_HOST}$", "0x3e7", wmiprvse,
                      r"C:\Windows\System32\services.exe")

        # 3) WmiPrvSE spawns cmd.exe -- the tip the alert fires on -- running as the
        #    authenticated deploy account (same logon id as the 4624 above).
        t += timedelta(seconds=self.rng.uniform(0.2, 0.8))
        dump_cmd = (
            f"cmd.exe /c rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump "
            f"{DUMP_PID} {DUMP_FILE} full"
        )
        self._process(t, VICTIM_HOST, ATTACK_USER, logon_id, r"C:\Windows\System32\cmd.exe",
                      wmiprvse, command_line=dump_cmd)
        self._sysmon_create(t, VICTIM_HOST, ATTACK_USER, r"C:\Windows\System32\cmd.exe",
                            wmiprvse, dump_cmd, logon_id)

        # 4) cmd spawns the dumper (rundll32 comsvcs MiniDump).
        t += timedelta(seconds=self.rng.uniform(0.1, 0.5))
        rundll_cmd = f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump {DUMP_PID} {DUMP_FILE} full"
        self._process(t, VICTIM_HOST, ATTACK_USER, logon_id, DUMPER_IMAGE,
                      r"C:\Windows\System32\cmd.exe", command_line=rundll_cmd)
        self._sysmon_create(t, VICTIM_HOST, ATTACK_USER, DUMPER_IMAGE,
                            r"C:\Windows\System32\cmd.exe", rundll_cmd, logon_id)

        # 5) the dumper reads lsass with the attack mask 0x1010.
        t += timedelta(seconds=self.rng.uniform(0.3, 1.2))
        call_trace = (
            r"C:\Windows\SYSTEM32\ntdll.dll+9c534|C:\Windows\System32\KERNELBASE.dll+2a24d|"
            r"C:\Windows\System32\comsvcs.dll+1a3f7|C:\Windows\System32\comsvcs.dll+1a1b2"
        )
        self._sysmon_access(t, VICTIM_HOST, DUMPER_IMAGE, ATTACK_GRANTED, call_trace)

        self.ground_truth.update({
            "attack_at": _iso(ATTACK_AT),
            "attack_logon_id": logon_id,
            "attack_user": ATTACK_USER,
            "attack_span_s": round((t - ATTACK_AT).total_seconds(), 1),
        })

    # -- background --------------------------------------------------------------------
    def _rand_ts(self) -> datetime:
        return WINDOW_START + timedelta(seconds=self.rng.uniform(0, SPAN_S))

    def background_logons(self, n: int) -> None:
        """Ordinary interactive (2) and network (3) logons with matching accounts, plus a
        few failures (4625). Type-3 from the file server is high volume and benign."""
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            user = self.rng.choice(USERS)
            sid = f"S-1-5-21-341049218-2894104772-1560093651-{self.rng.randint(1100, 1180)}"
            roll = self.rng.random()
            if roll < 0.55:
                self._logon(ts, host, user, sid, "2", "-", host, self._logon_id(),
                            proc="User32", pkg="Negotiate")
            elif roll < 0.9:
                self._logon(ts, host, user, sid, "3", FILESRV_IP, "SRV-FS01", self._logon_id())
            else:
                obj = {
                    "ts": _iso(ts), "event_id": 4625, "channel": "Security", "computer": host,
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "TargetUserName": user, "TargetDomainName": DOMAIN, "LogonType": "3",
                    "IpAddress": FILESRV_IP, "WorkstationName": "SRV-FS01",
                    "Status": "0xc000006d", "SubStatus": "0xc0000064",
                }
                self._emit(ts, "security", obj)

    def background_processes(self, n: int) -> None:
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            user = self.rng.choice(USERS)
            image = self.rng.choice(BENIGN_IMAGES).format(user=user)
            parent = r"C:\Windows\explorer.exe" if "svchost" not in image else \
                r"C:\Windows\System32\services.exe"
            logon_id = self._logon_id()
            self._process(ts, host, user, logon_id, image, parent)
            if self.rng.random() < 0.6:
                self._sysmon_create(ts, host, user, image, parent, f'"{image}"', logon_id)

    def background_lsass(self, n: int) -> None:
        """Legitimate lsass access every host sees constantly -- the noise the attack's
        one 0x1010 read has to be picked out of."""
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            image, mask = self.rng.choice(BENIGN_LSASS_READERS)
            self._sysmon_access(ts, host, image, mask,
                                r"C:\Windows\SYSTEM32\ntdll.dll+9c534|C:\Windows\System32\svchost.exe+1120")

    def background_dc(self, n: int) -> None:
        """Kerberos TGT/service tickets on the DC (4768/4769/4776) -- domain noise."""
        for _ in range(n):
            ts = self._rand_ts()
            user = self.rng.choice(USERS)
            eid = self.rng.choice([4768, 4769, 4776])
            obj = {
                "ts": _iso(ts), "event_id": eid, "channel": "Security", "computer": DC_HOST,
                "provider": "Microsoft-Windows-Security-Auditing",
                "TargetUserName": user, "TargetDomainName": DOMAIN,
                "IpAddress": self.rng.choice([ip for _h, ip in HOSTS]),
                "ServiceName": self.rng.choice(["krbtgt", "SRV-FS01$", "SRV-SQL01$"]),
                "TicketOptions": "0x40810010", "Status": "0x0",
            }
            self._emit(ts, "security", obj)

    # -- decoys ------------------------------------------------------------------------
    def decoy_management(self, n: int) -> None:
        """Killer decoy: an SCCM-style agent runs WmiPrvSE.exe -> cmd.exe inventory
        scripts on every host, including the victim, from the management server's service
        account. Same parent/child as the attack; different account, source and command,
        and no lsass touch."""
        wmiprvse = r"C:\Windows\System32\wbem\WmiPrvSE.exe"
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            logon_id = self._logon_id()
            self._logon(ts, host, MGMT_USER, "S-1-5-21-341049218-2894104772-1560093651-1009",
                        "3", MGMT_IP, MGMT_HOST, logon_id)
            t2 = ts + timedelta(seconds=self.rng.uniform(0.2, 0.6))
            cmd = (r"cmd.exe /c wmic /namespace:\\root\cimv2 path win32_quickfixengineering "
                   r"get hotfixid /format:csv > C:\Windows\CCM\inventory.tmp")
            self._process(t2, host, MGMT_USER, logon_id, r"C:\Windows\System32\cmd.exe",
                          wmiprvse, command_line=cmd)
            self._sysmon_create(t2, host, MGMT_USER, r"C:\Windows\System32\cmd.exe",
                                wmiprvse, cmd, logon_id)
        self.ground_truth["decoy_mgmt"] = n

    def decoy_av_lsass(self, n: int) -> None:
        """Antivirus reads lsass on every host every few minutes -- same TargetImage as
        the attack, mask 0x1000, honest MsMpEng.exe SourceImage."""
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            self._sysmon_access(ts, host, AV_IMAGE, "0x1000",
                                r"C:\Windows\SYSTEM32\ntdll.dll+9c534|"
                                r"C:\Program Files\Windows Defender\MpClient.dll+8a1c")
        self.ground_truth["decoy_av"] = n

    def decoy_admin_rdp(self, n: int) -> None:
        """Type-10 (RemoteInteractive) admin logons from the jump host to several hosts,
        the victim among them -- privileged remote access that is authorised."""
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            self._logon(ts, host, "t.admin", "S-1-5-21-341049218-2894104772-1560093651-1003",
                        "10", JUMP_IP, JUMP_HOST, self._logon_id(),
                        proc="Negotiate", pkg="Negotiate")
        self.ground_truth["decoy_rdp"] = n

    # -- render ------------------------------------------------------------------------
    def render(self, channel: str) -> str:
        rows = sorted((r for r in self.rows if r[1] == channel), key=lambda r: r[0])
        return "\n".join(json.dumps(obj, separators=(",", ":")) for _ts, _ch, obj in rows) + "\n"

    def count(self, channel: str) -> int:
        return sum(1 for r in self.rows if r[1] == channel)


def dhcp_log() -> str:
    """Lease records so both the victim and the attack's source host resolve to names.
    The victim's ACK is line 4 and its RENEW is line 8; the source host is line 6."""
    rows = [
        "2026-09-07 06:52:10 ACK 10.12.34.31 00:1b:44:11:3a:b7 WKS-3301 lease=28800",
        "2026-09-07 07:04:41 ACK 10.12.34.40 3c:22:fb:80:12:9e WKS-3340 lease=28800",
        "2026-09-07 07:19:55 ACK 10.12.34.51 00:1b:44:11:52:31 WKS-3351 lease=28800",
        f"2026-09-07 07:33:08 ACK {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
        "2026-09-07 07:41:22 ACK 10.12.34.8 00:25:90:aa:31:7d SRV-SCCM01 lease=86400",
        f"2026-09-07 07:58:47 ACK {SOURCE_IP} {SOURCE_MAC} {SOURCE_HOST} lease=28800",
        "2026-09-07 08:06:03 ACK 10.12.34.32 00:1b:44:11:3a:c1 WKS-3312 lease=28800",
        f"2026-09-07 11:33:08 RENEW {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
    ]
    return "\n".join(rows) + "\n"


def alert_json() -> dict:
    return {
        "alert_id": "SENTINEL-2026-09-07-0071204",
        "detector": "sysmon-sigma",
        "rule_name": "Process Creation: cmd.exe Spawned by WmiPrvSE.exe",
        "status": "open",
        "severity": "high",
        "first_seen": "2026-09-07T10:31:00Z",
        "last_seen": "2026-09-07T10:31:04Z",
        "summary": (
            f"A Sigma process-creation rule matched on {VICTIM_HOST}: cmd.exe was created "
            f"with WmiPrvSE.exe as its parent, a common signature of remote command "
            f"execution over WMI. The rule inspects only the parent/child image pair on "
            f"this one host; it does not evaluate the logon that preceded it, the account "
            f"used, the source of any network logon, or subsequent process-access events."
        ),
        "entities": [
            {"kind": "host", "value": VICTIM_HOST, "note": "host where the process was created"},
            {"kind": "process", "value": "WmiPrvSE.exe", "note": "parent process in the match"},
        ],
        "raw_detector_fields": {
            "product": "sysmon-sigma",
            "rule_id": "d21c3f1a-2b7e-4c0e-9d3a-7f5b2e9c1a44",
            "sigma_level": "high",
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "event_id": "1",
            "mitre": "T1047",
        },
    }


def ground_truth_md(stats: dict) -> str:
    return f"""# Ground truth — cases/wmi-lsass

Generated by `scripts/make_wmi_lsass_case.py` (seed {SEED}). This file sits at the case
root, **not** in `logs/`, so `analyze.py` never reads it. Use it to grade the brief.

Windows host telemetry (Security + Sysmon), one JSON object per line. Derived from two
public EVTX-ATTACK-SAMPLES recordings ({stats['evtx_source_records']}); every identifier
has been re-seeded, so nothing here matches a memorised sample.

## What actually happened

A WMI lateral-movement into a credential dump on **{VICTIM_HOST} / {VICTIM_IP}**, in one
short chain at **{stats['attack_at']}** (~{stats['attack_span_s']} s end to end):

- **A network (type-3) logon to the victim as `{DOMAIN}\\{ATTACK_USER}`** — a privileged
  deployment service account — **from {SOURCE_IP} ({SOURCE_HOST})**, another workstation,
  not an admin console. `{ATTACK_USER}` driving an interactive-style WMI exec is the anomaly.
- **`WmiPrvSE.exe` spawned `cmd.exe`** (the alert's tip) running as `{ATTACK_USER}` under
  logon id `{stats['attack_logon_id']}` — the *same* id as the type-3 logon, which is what
  ties the process to the logon and the logon to {SOURCE_IP}.
- **The command dumped LSASS**: `cmd.exe` ran `rundll32.exe … comsvcs.dll, MiniDump` and a
  process then read **lsass.exe with GrantedAccess {ATTACK_GRANTED}** (read+query, the mask
  a credential dumper needs).
- **Timing: a single ~80 s chain**, once. Not periodic, not repeating sessions — the third
  timing signature after dns-tunnel's bursts and http-c2's beacon. `timeline` over the
  attack pattern should show one cluster.

## The decoys — all benign, all shaped like a piece of the attack

A brief that flags any of these as the intrusion is producing false positives:

1. **SCCM management agent** ({stats['decoy_mgmt']} runs) — `WmiPrvSE.exe → cmd.exe` on
   every host **including the victim**, from `{MGMT_HOST}` ({MGMT_IP}) as `{MGMT_USER}`.
   The *exact parent/child pair the alert matches*, everywhere, all day. Benign: a
   hotfix-inventory `wmic` command, a service account, no lsass access. This is the decoy
   that proves the WmiPrvSE→cmd signature alone is not the intrusion.
2. **Antivirus LSASS access** ({stats['decoy_av']}) — `MsMpEng.exe` reads `lsass.exe` on
   every host every few minutes, GrantedAccess `0x1000`. Same TargetImage as the attack;
   the discriminator is the SourceImage and the mask, not that lsass was touched.
3. **Admin RDP** ({stats['decoy_rdp']}) — type-10 logons from the jump host `{JUMP_HOST}`
   ({JUMP_IP}) to several hosts including the victim. Privileged remote access, authorised.
4. **Backup service** — high-volume type-3 logons from the file server, a service account,
   the ordinary weight of network logons the one attacker logon hides in.

## Grading the brief

A good brief should:

- name the **source of the type-3 logon** — {SOURCE_IP}, and {SOURCE_HOST} via `dhcp.log`;
- name the **account** `{ATTACK_USER}` and that it is privileged / out of place;
- tie the logon to the process via the shared **logon id** `{stats['attack_logon_id']}`
  (4624 TargetLogonId → 4688 SubjectLogonId);
- quote the **WmiPrvSE → cmd** command line (the comsvcs MiniDump);
- identify the **lsass access at GrantedAccess {ATTACK_GRANTED}** and distinguish it from
  the antivirus `0x1000` reads;
- describe the timing as **a single short chain**, not periodic or repeating;
- **not** flag the four decoys — especially the SCCM WmiPrvSE→cmd runs — or if it mentions
  them, explicitly distinguish them;
- record what it could not determine — there is no network capture or file-write content
  here, so what left the host cannot be confirmed from this data.

## Volumes

| | lines |
|---|---|
| total events | {stats['total']} |
| security.jsonl | {stats['security']} |
| sysmon.jsonl | {stats['sysmon']} |
| attack chain | {stats['attack_events']} |
| SCCM decoy | {stats['decoy_mgmt']} logon+proc pairs |
| AV lsass decoy | {stats['decoy_av']} |
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="cases/wmi-lsass")
    parser.add_argument("--evtx-dir", default="cases/_evtx")
    parser.add_argument("--target-mb", type=float, default=1.4)
    args = parser.parse_args()

    rng = random.Random(SEED)
    gen = Generator(rng, Path(args.evtx_dir))

    gen.attack()
    attack_events = len(gen.rows)
    gen.decoy_management(90)
    gen.decoy_av_lsass(260)
    gen.decoy_admin_rdp(70)

    # Background fill, measured against the total byte target across both files.
    target_bytes = int(args.target_mb * 1_000_000)
    gen.background_logons(400)
    gen.background_processes(400)
    gen.background_lsass(300)
    gen.background_dc(200)
    for _ in range(3):
        size = len(gen.render("security")) + len(gen.render("sysmon"))
        if size >= target_bytes:
            break
        recent = gen.rows[-400:]
        per_line = sum(len(json.dumps(o, separators=(",", ":"))) for _t, _c, o in recent) / len(recent)
        need = int((target_bytes - size) / per_line)
        gen.background_logons(max(1, need // 3))
        gen.background_processes(max(1, need // 3))
        gen.background_lsass(max(1, need // 4))

    out = Path(args.out)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    sec, sysm = gen.render("security"), gen.render("sysmon")
    (out / "logs" / "security.jsonl").write_text(sec, encoding="utf-8")
    (out / "logs" / "sysmon.jsonl").write_text(sysm, encoding="utf-8")
    (out / "logs" / "dhcp.log").write_text(dhcp_log(), encoding="utf-8")
    (out / "alert.json").write_text(json.dumps(alert_json(), indent=2) + "\n", encoding="utf-8")

    stats = {
        **gen.ground_truth,
        "attack_events": attack_events,
        "security": gen.count("security"),
        "sysmon": gen.count("sysmon"),
        "total": len(gen.rows),
    }
    (out / "GROUND_TRUTH.md").write_text(ground_truth_md(stats), encoding="utf-8")

    print(f"wrote {out}/")
    print(f"  logs/security.jsonl  {stats['security']} events")
    print(f"  logs/sysmon.jsonl    {stats['sysmon']} events")
    print("  logs/dhcp.log        8 leases")
    print(f"  alert.json           sysmon-sigma WmiPrvSE->cmd on {VICTIM_HOST}")
    print("  GROUND_TRUTH.md      not read by analyze.py")
    print(f"  attack: {attack_events} events at {stats['attack_at']}, "
          f"logon id {stats['attack_logon_id']}, lsass {ATTACK_GRANTED}; "
          f"decoys: {stats['decoy_mgmt']} SCCM, {stats['decoy_av']} AV")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
