"""Windows-specific detection rules."""
from __future__ import annotations

import re
from typing import Dict, Iterable

from ..models import Bundle
from ..util import basename_any, lower
from .engine import rule
from . import patterns as P


def _proc_index(b: Bundle):
    return {p.get("pid"): p for p in b.get("processes")}


# ------------------------------------------------------------------ processes
@rule("WIN-PROC-001", "System binary running from a non-system path", "high", "processes",
      technique="T1036.005", tactic="Defense Evasion", platform="windows",
      description="A protected Windows binary name is executing from outside System32/SysWOW64, a hallmark of masquerading.",
      recommendation="Hash the image and compare to the known-good System32 copy; treat as suspected masquerade until cleared.")
def win_sysbin_path(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        name = basename_any(p.get("name") or "")
        exe = p.get("exe") or ""
        if name in P.WIN_SYSTEM_BINARIES and exe and not P.WIN_SYSTEM_DIR.search(exe):
            yield {"process": name, "pid": p.get("pid"), "exe": exe, "cmdline": (p.get("cmdline") or "")[:300],
                   "user": p.get("user"), "signature": p.get("signature"), "_timestamp": p.get("start_time"),
                   "_tags": ["masquerade"]}


@rule("WIN-PROC-002", "Process name mimics a system binary", "high", "processes",
      technique="T1036.005", tactic="Defense Evasion", platform="windows",
      description="A process name is a near-spelling of a core Windows binary (e.g. a zero for an o).",
      recommendation="Any lookalike of a system binary should be isolated and the image submitted for analysis.")
def win_lookalike(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        name = basename_any(p.get("name") or "")
        if P.WIN_LOOKALIKES.match(name):
            yield {"process": name, "pid": p.get("pid"), "exe": p.get("exe"), "cmdline": (p.get("cmdline") or "")[:300],
                   "user": p.get("user"), "_timestamp": p.get("start_time"), "_tags": ["masquerade", "typosquat"]}


@rule("WIN-PROC-003", "Unexpected parent/child process relationship", "medium", "processes",
      technique="T1036", tactic="Defense Evasion", platform="windows",
      description="A core process has a parent it should never have (e.g. lsass.exe not spawned by wininit.exe).",
      recommendation="Unexpected ancestry of lsass/services/csrss is a strong tampering signal; investigate the parent.")
def win_parent_child(b: Bundle) -> Iterable[Dict]:
    idx = _proc_index(b)
    for p in b.get("processes"):
        name = basename_any(p.get("name") or "")
        expected = P.WIN_EXPECTED_PARENT.get(name)
        if not expected:
            continue
        parent = idx.get(p.get("ppid"))
        pname = basename_any(parent.get("name")) if parent else "(exited)"
        if pname and pname != "(exited)" and pname not in expected:
            yield {"process": name, "pid": p.get("pid"), "parent": pname, "ppid": p.get("ppid"),
                   "expected_parent": sorted(expected), "exe": p.get("exe"), "user": p.get("user"),
                   "_timestamp": p.get("start_time"), "_tags": ["process-ancestry"]}


@rule("WIN-PROC-004", "Office or browser spawned a shell or script host", "high", "processes",
      technique="T1059", tactic="Execution", platform="windows",
      description="A document/mail/browser application is the parent of a command shell or script interpreter, a classic macro/exploit chain.",
      recommendation="Pull the parent document and the child command line; this pattern is rarely benign.")
def win_office_child(b: Bundle) -> Iterable[Dict]:
    idx = _proc_index(b)
    for p in b.get("processes"):
        name = basename_any(p.get("name") or "")
        if name not in P.SHELLS_AND_SCRIPT_HOSTS:
            continue
        parent = idx.get(p.get("ppid"))
        pname = basename_any(parent.get("name")) if parent else ""
        if pname in P.OFFICE_APPS or pname in P.BROWSERS_AND_READERS:
            yield {"parent": pname, "process": name, "pid": p.get("pid"), "cmdline": (p.get("cmdline") or "")[:400],
                   "user": p.get("user"), "_timestamp": p.get("start_time"), "_severity": "high",
                   "_tags": ["suspicious-child"]}


@rule("WIN-PROC-005", "LOLBin command-line signature", "high", "processes",
      technique="T1218", tactic="Defense Evasion", platform="windows",
      description="A living-off-the-land binary was invoked with arguments matching a known abuse pattern.",
      recommendation="Map the signature to its technique and confirm whether the invocation fits any legitimate admin task.")
def win_lolbin(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        cmd = p.get("cmdline") or ""
        labels = list(P.hits(P.LOLBIN_PATTERNS, cmd))
        if not labels:
            continue
        techs = sorted({t for _, t in labels})
        names = sorted({n for n, _ in labels})
        yield {"process": basename_any(p.get("name")), "pid": p.get("pid"), "cmdline": cmd[:500], "matched": names,
               "techniques": techs, "user": p.get("user"), "_timestamp": p.get("start_time"),
               "_description": "Command line matched: " + ", ".join(names), "_tags": ["lolbin"],
               "_technique": techs[0] if techs else "T1218"}


@rule("WIN-PROC-006", "PowerShell with obfuscation / download / injection signature", "high", "processes",
      technique="T1059.001", tactic="Execution", platform="windows",
      description="A PowerShell command line matches encoding, download-cradle, or in-memory execution patterns.",
      recommendation="Decode any encoded block offline and reconstruct the intent; correlate with 4104 script-block logs.")
def win_ps_cmdline(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        name = basename_any(p.get("name"))
        if name not in ("powershell.exe", "pwsh.exe"):
            continue
        cmd = p.get("cmdline") or ""
        labels = list(P.hits(P.PS_SUSPICIOUS, cmd))
        if not labels:
            continue
        names = sorted({n for n, _ in labels})
        yield {"pid": p.get("pid"), "cmdline": cmd[:600], "matched": names, "user": p.get("user"),
               "_timestamp": p.get("start_time"), "_description": "PowerShell matched: " + ", ".join(names),
               "_severity": "critical" if "known offensive toolkit name" in names else "high", "_tags": ["powershell"]}


@rule("WIN-PROC-007", "Unsigned or untrusted process image", "low", "processes",
      technique="T1036", tactic="Defense Evasion", platform="windows",
      description="A running image is not validly signed. Benign for much third-party software, notable from suspicious paths.",
      recommendation="Prioritise unsigned images running from user-writable or temp directories.")
def win_unsigned(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        sig = lower(p.get("signature"))
        exe = p.get("exe") or ""
        if not sig or sig in ("valid",):
            continue
        if sig in ("notsigned", "unknownerror", "hashmismatch", "notrusted", "unknown"):
            sev = "low"
            tags = ["unsigned"]
            if exe and P.WIN_SUSPICIOUS_DIR.search(exe):
                sev = "high"
                tags.append("suspicious-path")
            yield {"process": basename_any(p.get("name")), "pid": p.get("pid"), "exe": exe, "signature": p.get("signature"),
                   "user": p.get("user"), "_severity": sev, "_timestamp": p.get("start_time"), "_tags": tags}


# ------------------------------------------------------------------ services
@rule("WIN-SVC-001", "Service image in a suspicious path", "high", "services",
      technique="T1543.003", tactic="Persistence", platform="windows",
      description="A Windows service runs a binary from a temp/user/public directory rather than a program location.",
      recommendation="Services almost never legitimately live in temp/user paths; treat as persistence until proven otherwise.")
def win_svc_path(b: Bundle) -> Iterable[Dict]:
    for s in b.get("services"):
        path = s.get("path") or ""
        m = re.search(r'("?)([a-z]:\\[^"]+?\.(?:exe|dll|sys|ps1|bat|cmd|vbs|js))', path, re.I)
        img = m.group(2) if m else path
        if img and P.WIN_SUSPICIOUS_DIR.search(img):
            yield {"service": s.get("name"), "display_name": s.get("display_name"), "path": path,
                   "account": s.get("account"), "start_mode": s.get("start_mode"), "state": s.get("state"),
                   "_tags": ["service-persistence"]}


@rule("WIN-SVC-002", "Service runs an interpreter or LOLBin", "high", "services",
      technique="T1543.003", tactic="Persistence", platform="windows",
      description="A service's ImagePath invokes cmd/powershell/rundll32/etc. rather than a dedicated service binary.",
      recommendation="Reconstruct the full command; interpreter-backed services are a common persistence mechanism.")
def win_svc_interp(b: Bundle) -> Iterable[Dict]:
    for s in b.get("services"):
        path = lower(s.get("path") or "")
        if not path:
            continue
        if any(tok in path for tok in ("powershell", "cmd.exe", "cmd /", "rundll32", "mshta", "wscript", "cscript",
                                       "regsvr32", "\\temp\\", "certutil", "bitsadmin", "msbuild")):
            labels = [n for n, _ in P.hits(P.LOLBIN_PATTERNS, s.get("path") or "")]
            yield {"service": s.get("name"), "path": s.get("path"), "account": s.get("account"),
                   "start_mode": s.get("start_mode"), "matched": labels, "_tags": ["service-persistence", "lolbin"]}


# ----------------------------------------------------------- scheduled tasks
@rule("WIN-TASK-001", "Scheduled task runs a suspicious command", "high", "scheduled_tasks",
      technique="T1053.005", tactic="Persistence", platform="windows",
      description="A scheduled task's action invokes an interpreter, LOLBin, or a binary from a suspicious path.",
      recommendation="Check the task author and creation time; attacker tasks often run as SYSTEM at logon or on a short interval.")
def win_task(b: Bundle) -> Iterable[Dict]:
    for t in b.get("scheduled_tasks"):
        cmd = t.get("command") or ""
        low = lower(cmd)
        if low in ("", "n/a", "cof task"):
            continue
        labels = [n for n, _ in P.hits(P.LOLBIN_PATTERNS + P.PS_SUSPICIOUS, cmd)]
        susp_path = bool(P.WIN_SUSPICIOUS_DIR.search(cmd))
        interp = any(tok in low for tok in ("powershell", "cmd.exe", "cmd /", "rundll32", "mshta", "wscript", "cscript",
                                            "regsvr32", "certutil", "bitsadmin", "curl", "\\temp\\", "\\appdata\\"))
        urlhit = bool(P.SUSPICIOUS_URL.search(cmd))
        if labels or susp_path or urlhit or (interp and t.get("run_as", "").upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM")):
            yield {"task": t.get("name"), "command": cmd[:500], "run_as": t.get("run_as"), "author": t.get("author"),
                   "schedule": t.get("schedule"), "matched": labels, "status": t.get("status"),
                   "created": t.get("xml_ctime"), "_severity": "high" if (labels or susp_path or urlhit) else "medium",
                   "_tags": ["task-persistence"]}


# ------------------------------------------------------------------ autoruns
@rule("WIN-RUN-001", "Autostart entry points at a suspicious command", "high", "autoruns",
      technique="T1547.001", tactic="Persistence", platform="windows",
      description="A Run key / startup entry launches an interpreter, LOLBin, or a binary from a temp/user path.",
      recommendation="Autostart is the most common persistence location; validate each entry against the installed software.")
def win_autorun(b: Bundle) -> Iterable[Dict]:
    for a in b.get("autoruns"):
        val = a.get("value") or ""
        low = lower(val)
        if not val:
            continue
        labels = [n for n, _ in P.hits(P.LOLBIN_PATTERNS + P.PS_SUSPICIOUS, val)]
        susp = bool(P.WIN_SUSPICIOUS_DIR.search(val))
        urlhit = bool(P.SUSPICIOUS_URL.search(val))
        interp = any(tok in low for tok in ("powershell", "mshta", "rundll32", "regsvr32", "wscript", "cscript",
                                            "cmd /c", "cmd.exe /c", "certutil", "bitsadmin"))
        key = lower(a.get("key"))
        # Winlogon Shell/Userinit hijack
        hijack = a.get("name", "").lower() in ("shell", "userinit") and ("explorer.exe" not in low and "userinit.exe" not in low)
        if labels or susp or urlhit or interp or hijack:
            yield {"key": a.get("key"), "name": a.get("name"), "value": val[:500], "source": a.get("source"),
                   "matched": labels, "_severity": "high" if (labels or susp or urlhit or hijack) else "medium",
                   "_tags": ["autostart"] + (["winlogon-hijack"] if hijack else [])}


@rule("WIN-RUN-002", "Image File Execution Options debugger hijack", "high", "autoruns",
      technique="T1546.012", tactic="Persistence", platform="windows",
      description="An IFEO 'Debugger' value redirects a program to another executable; also used for accessibility-key backdoors.",
      recommendation="Any Debugger value (especially on sethc.exe, utilman.exe, osk.exe, magnify.exe) should be investigated.")
def win_ifeo(b: Bundle) -> Iterable[Dict]:
    for a in b.get("autoruns"):
        key = lower(a.get("key"))
        name = lower(a.get("name"))
        if "image file execution options" in key and name in ("debugger", "globalflag", "monitorprocess"):
            yield {"key": a.get("key"), "name": a.get("name"), "value": a.get("value"),
                   "_severity": "high" if name == "debugger" else "medium", "_tags": ["ifeo"]}
        if "silentprocessexit" in key and name in ("monitorprocess", "reportingmode"):
            yield {"key": a.get("key"), "name": a.get("name"), "value": a.get("value"), "_tags": ["silentprocessexit"]}


# ----------------------------------------------------------------------- WMI
@rule("WIN-WMI-001", "WMI permanent event subscription present", "high", "wmi_subscriptions",
      technique="T1546.003", tactic="Persistence", platform="windows",
      description="A permanent WMI event filter/consumer binding survives reboot and executes on a trigger — a stealthy persistence mechanism.",
      recommendation="Permanent WMI subscriptions are rare in normal estates; review the consumer command and the filter query.")
def win_wmi(b: Bundle) -> Iterable[Dict]:
    for w in b.get("wmi_subscriptions"):
        if w.get("kind") == "consumer":
            payload = w.get("CommandLineTemplate") or w.get("ScriptText") or w.get("ExecutablePath") or ""
            yield {"name": w.get("Name"), "class": w.get("class"), "payload": str(payload)[:500],
                   "_severity": "high", "_tags": ["wmi-persistence"]}
        elif w.get("kind") == "binding":
            yield {"filter": w.get("Filter"), "consumer": w.get("Consumer"), "class": w.get("class"),
                   "_severity": "medium", "_tags": ["wmi-persistence"], "_title": "WMI filter-to-consumer binding"}


# -------------------------------------------------------------------- events
@rule("WIN-EVT-001", "Security audit log cleared", "high", "events",
      technique="T1070.001", tactic="Defense Evasion", platform="windows",
      description="Event ID 1102 (Security) or 104 (System) records that an event log was cleared.",
      recommendation="Log clearing immediately before/after suspected activity is a strong anti-forensic indicator; note the account.")
def win_log_cleared(b: Bundle) -> Iterable[Dict]:
    for e in b.get("events"):
        eid = e.get("event_id")
        if eid in (1102, 104):
            d = e.get("data", {})
            who = d.get("SubjectUserName") or d.get("UserName") or d.get("param1") or ""
            yield {"event_id": eid, "channel": e.get("channel"), "user": who, "_timestamp": e.get("timestamp"),
                   "_tags": ["log-cleared"]}


@rule("WIN-EVT-002", "New service installed (7045)", "medium", "events",
      technique="T1543.003", tactic="Persistence", platform="windows",
      description="A service was installed. Attacker tooling (PsExec, Cobalt Strike, ransomware) installs transient services.",
      recommendation="Correlate the service name and image path with the 7045 timestamp; random-looking names are suspicious.")
def win_7045(b: Bundle) -> Iterable[Dict]:
    for e in b.get("events"):
        if e.get("event_id") == 7045:
            d = e.get("data", {})
            name = d.get("ServiceName", "")
            img = d.get("ImagePath", "")
            labels = [n for n, _ in P.hits(P.LOLBIN_PATTERNS + P.PS_SUSPICIOUS, img)]
            rnd = bool(re.match(r"^[a-z0-9]{6,16}$", name, re.I) and not re.search(r"[aeiou]{1}", name, re.I))
            sev = "high" if (labels or P.WIN_SUSPICIOUS_DIR.search(img or "") or rnd) else "medium"
            yield {"service": name, "image": img[:400], "type": d.get("ServiceType"), "start": d.get("StartType"),
                   "account": d.get("AccountName"), "matched": labels, "random_name": rnd,
                   "_timestamp": e.get("timestamp"), "_severity": sev, "_tags": ["service-install"]}


@rule("WIN-EVT-003", "Encoded/suspicious PowerShell in script-block log (4104)", "high", "events",
      technique="T1059.001", tactic="Execution", platform="windows",
      description="A PowerShell script-block (4104) or module log (4103) contains obfuscation or offensive tooling signatures.",
      recommendation="Script-block logs capture de-obfuscated content; read the full block to establish intent.")
def win_4104(b: Bundle) -> Iterable[Dict]:
    for e in b.get("events"):
        if e.get("event_id") in (4103, 4104):
            block = e.get("data", {}).get("ScriptBlockText") or e.get("data", {}).get("Payload") or e.get("message") or ""
            labels = [n for n, _ in P.hits(P.PS_SUSPICIOUS, block)]
            if labels:
                yield {"event_id": e.get("event_id"), "matched": sorted(set(labels)), "excerpt": block[:400],
                       "_timestamp": e.get("timestamp"),
                       "_severity": "critical" if "known offensive toolkit name" in labels else "high",
                       "_tags": ["script-block"]}


@rule("WIN-EVT-004", "Repeated logon failures then success (possible brute force)", "medium", "events",
      technique="T1110", tactic="Credential Access", platform="windows",
      description="A burst of 4625 failures for an account followed by a 4624 success can indicate a successful password-guessing attack.",
      recommendation="Check the source IP/workstation and the count; confirm whether the eventual success is the attacker.")
def win_bruteforce(b: Bundle) -> Iterable[Dict]:
    from collections import defaultdict
    fails = defaultdict(list)
    success = defaultdict(list)
    for e in b.get("events"):
        d = e.get("data", {})
        user = lower(d.get("TargetUserName"))
        if not user or user in ("-", "system"):
            continue
        if e.get("event_id") == 4625:
            fails[user].append((e.get("timestamp"), d.get("IpAddress") or d.get("WorkstationName")))
        elif e.get("event_id") == 4624 and d.get("LogonType") in ("3", "10", "2"):
            success[user].append((e.get("timestamp"), d.get("IpAddress")))
    for user, fl in fails.items():
        if len(fl) >= 5:
            sources = sorted({s for _, s in fl if s})
            yield {"user": user, "failures": len(fl), "sources": sources[:10],
                   "followed_by_success": bool(success.get(user)),
                   "_severity": "high" if success.get(user) else "medium",
                   "_timestamp": fl[-1][0], "_tags": ["brute-force"]}


@rule("WIN-DEF-001", "Defender disabled, tampered, or exclusion added", "high", "defender",
      technique="T1562.001", tactic="Defense Evasion", platform="windows",
      description="Real-time protection is off, tamper protection is off, or a path/process/extension exclusion has been configured.",
      recommendation="Attacker-added exclusions often point at their staging directory; review each exclusion path.")
def win_defender(b: Bundle) -> Iterable[Dict]:
    for d in b.get("defender"):
        if d.get("kind") == "status":
            for key, val in (("RealTimeProtectionEnabled", d.get("RealTimeProtectionEnabled")),
                             ("IsTamperProtected", d.get("IsTamperProtected")),
                             ("AntivirusEnabled", d.get("AntivirusEnabled"))):
                if val is False or lower(val) == "false":
                    yield {"setting": key, "value": val, "_severity": "high", "_tags": ["defender-off"],
                           "_title": f"Defender: {key} is off"}
        elif d.get("kind") == "preferences":
            for key in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension"):
                vals = d.get(key)
                if vals:
                    items = vals if isinstance(vals, list) else [vals]
                    yield {"setting": key, "values": items, "_severity": "medium", "_tags": ["defender-exclusion"],
                           "_title": f"Defender exclusion set ({key})"}
            for key in ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableScriptScanning", "DisableIOAVProtection"):
                if d.get(key) is True or lower(d.get(key)) == "true":
                    yield {"setting": key, "value": True, "_severity": "high", "_tags": ["defender-off"],
                           "_title": f"Defender: {key} enabled"}


# --------------------------------------------------------------------- users
@rule("WIN-USR-001", "Hidden or recently created privileged account", "medium", "users",
      technique="T1136.001", tactic="Persistence", platform="windows",
      description="A local account ending in '$' is hidden from the logon UI; recently-created admin accounts can be attacker persistence.",
      recommendation="Validate each privileged local account against your provisioning records.")
def win_hidden_user(b: Bundle) -> Iterable[Dict]:
    for u in b.get("users"):
        tags, sev = [], "low"
        if u.get("hidden_from_logon"):
            tags.append("hidden-account")
            sev = "high"
        if u.get("privileged_groups"):
            tags.append("privileged")
            sev = "medium" if sev == "low" else sev
        if tags:
            yield {"name": u.get("name"), "enabled": u.get("enabled"), "groups": u.get("privileged_groups"),
                   "pw_last_set": u.get("pw_last_set"), "last_logon": u.get("last_logon"),
                   "domain_principal": u.get("domain_principal"), "_severity": sev, "_tags": tags}


@rule("WIN-FILE-001", "Recently dropped executable in user/public path", "medium", "recent_files",
      technique="T1105", tactic="Command and Control", platform="windows",
      description="An executable, script, or container file appeared recently in a download/temp/public directory.",
      recommendation="Cross-reference against process creation and browser/mail history to establish how it arrived.")
def win_recent_drop(b: Bundle) -> Iterable[Dict]:
    for f in b.get("recent_files"):
        ext = lower(f.get("ext"))
        if ext in (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".scr", ".jar", ".wsf", ".msi"):
            sev = "high" if (f.get("path") and P.WIN_SUSPICIOUS_DIR.search(f["path"]) and ext in (".exe", ".scr", ".hta", ".ps1")) else "medium"
            yield {"path": f.get("path"), "ext": ext, "size": f.get("size"), "sha256": f.get("sha256"),
                   "_timestamp": f.get("mtime"), "_severity": sev, "_tags": ["dropped-file"]}
