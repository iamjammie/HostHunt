"""Live Windows artefact collector.

Uses PowerShell / built-in binaries only (no third-party dependencies) so it can
be dropped onto a box from a USB stick or pushed via your EDR's RTR / PSExec.
Run from an elevated prompt for full coverage (Security log, all processes).
"""
from __future__ import annotations

import csv
import glob
import io
import json
import os
import socket
import time
from typing import Any, Dict, List, Optional

from ..models import Bundle, now_iso
from ..parse.evtx_xml import parse_wevtutil_xml
from ..util import file_times, run, sha256_file

PS = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]

# Registry autostart locations (Autoruns-style, trimmed to the high-value set)
AUTORUN_KEYS = [
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders",
    r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
    r"HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
    r"HKLM:\SOFTWARE\Classes\exefile\shell\open\command",
    r"HKLM:\SOFTWARE\Classes\CLSID\{42aedc87-2188-41fd-b9a3-0c966feabec1}\InprocServer32",
    r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjectDelayLoad",
    r"HKLM:\SOFTWARE\Microsoft\Netsh",
    r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    r"HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKCU:\SOFTWARE\Classes\exefile\shell\open\command",
    r"HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command",
    r"HKCU:\SOFTWARE\Classes\mscfile\shell\open\command",
    r"HKCU:\Environment",
]

# Channel -> (XPath event id filter, approx count). Keep the set tight; a full pull is a
# job for KAPE / velociraptor, this is the "what do I need in the first hour" set.
EVENT_QUERIES = {
    "Security": "*[System[(EventID=1102 or EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or "
                "EventID=4688 or EventID=4697 or EventID=4698 or EventID=4699 or EventID=4702 or EventID=4719 or "
                "EventID=4720 or EventID=4722 or EventID=4724 or EventID=4726 or EventID=4728 or EventID=4732 or "
                "EventID=4738 or EventID=4756 or EventID=4768 or EventID=4769 or EventID=4771 or EventID=4776 or "
                "EventID=4794 or EventID=5140 or EventID=5145 or EventID=4657 or EventID=4663 or EventID=4670)]]",
    "System": "*[System[(EventID=7045 or EventID=7034 or EventID=7036 or EventID=7040 or EventID=104 or "
              "EventID=1074 or EventID=6005 or EventID=6006 or EventID=6008 or EventID=7030 or EventID=7024 or EventID=4697)]]",
    "Microsoft-Windows-PowerShell/Operational": "*[System[(EventID=4103 or EventID=4104)]]",
    "Windows PowerShell": "*[System[(EventID=400 or EventID=403 or EventID=600 or EventID=800)]]",
    "Microsoft-Windows-Sysmon/Operational": "*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=8 or EventID=10 or "
                                            "EventID=11 or EventID=12 or EventID=13 or EventID=17 or EventID=19 or EventID=20 or EventID=21 or EventID=22 or EventID=25)]]",
    "Microsoft-Windows-TaskScheduler/Operational": "*[System[(EventID=106 or EventID=140 or EventID=141 or EventID=200 or EventID=201)]]",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": "*[System[(EventID=21 or EventID=22 or EventID=24 or EventID=25)]]",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": "*[System[(EventID=1149)]]",
    "Microsoft-Windows-Windows Defender/Operational": "*[System[(EventID=1006 or EventID=1007 or EventID=1015 or EventID=1116 or EventID=1117 or "
                                                       "EventID=5001 or EventID=5004 or EventID=5007 or EventID=5010 or EventID=5012 or EventID=5013)]]",
    "Microsoft-Windows-WMI-Activity/Operational": "*[System[(EventID=5857 or EventID=5858 or EventID=5859 or EventID=5860 or EventID=5861)]]",
    "Microsoft-Windows-Bits-Client/Operational": "*[System[(EventID=59 or EventID=60)]]",
    "Microsoft-Windows-WinRM/Operational": "*[System[(EventID=91 or EventID=168)]]",
    "Microsoft-Windows-SmbClient/Security": "*[System[(EventID=31001)]]",
    "Application": "*[System[(EventID=1000 or EventID=1001 or EventID=1026 or EventID=4625)]]",
}


def ps_json(script: str, timeout: int = 120) -> Any:
    out = run(PS + [script + " | ConvertTo-Json -Depth 4 -Compress"], timeout)
    out = out.strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        return [data]
    return data


class WindowsCollector:
    def __init__(self, hash_files: bool = False, event_limit: int = 5000, quick: bool = False):
        self.hash_files = hash_files
        self.event_limit = event_limit
        self.quick = quick
        self.bundle = Bundle(host=socket.gethostname())
        self.windir = os.environ.get("SystemRoot", r"C:\Windows")

    def collect(self) -> Bundle:
        steps = [
            ("host", self.collect_host), ("processes", self.collect_processes),
            ("services", self.collect_services), ("drivers", self.collect_drivers),
            ("scheduled_tasks", self.collect_tasks), ("autoruns", self.collect_autoruns),
            ("wmi_subscriptions", self.collect_wmi), ("network", self.collect_network),
            ("users", self.collect_users), ("prefetch", self.collect_prefetch),
            ("events", self.collect_events), ("defender", self.collect_defender),
            ("named_pipes", self.collect_pipes), ("dns", self.collect_dns),
            ("shares", self.collect_shares), ("recent_files", self.collect_recent_files),
            ("shell_history", self.collect_ps_history), ("firewall", self.collect_firewall),
        ]
        for name, fn in steps:
            t0 = time.time()
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                self.bundle.errors.append(f"{name}: {exc!r}")
            self.bundle.meta.setdefault("timings", {})[name] = round(time.time() - t0, 2)
        return self.bundle

    # ---------------------------------------------------------------- host
    def collect_host(self) -> None:
        info = ps_json("Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,"
                       "InstallDate,OSArchitecture,CSName,LocalDateTime,CurrentTimeZone")
        cs = ps_json("Get-CimInstance Win32_ComputerSystem | Select-Object Domain,PartOfDomain,Manufacturer,Model,UserName")
        ifaces = ps_json("Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -ne '127.0.0.1'} | "
                         "Select-Object InterfaceAlias,IPAddress")
        o = info[0] if info else {}
        c = cs[0] if cs else {}
        self.bundle.meta.update({
            "hostname": socket.gethostname(), "platform": "windows", "collector": "hosthunt-windows",
            "os": f"{o.get('Caption','')} {o.get('Version','')} build {o.get('BuildNumber','')}".strip(),
            "arch": o.get("OSArchitecture"), "boot_time": o.get("LastBootUpTime"), "install_date": o.get("InstallDate"),
            "domain": c.get("Domain"), "part_of_domain": c.get("PartOfDomain"), "logged_on": c.get("UserName"),
            "collected_at": now_iso(), "local_time": o.get("LocalDateTime"), "tz_offset_min": o.get("CurrentTimeZone"),
            "interfaces": [{"iface": i.get("InterfaceAlias"), "addr": i.get("IPAddress")} for i in ifaces],
            "elevated": "True" in run(PS + ["([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
                                            ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"]),
        })

    # ----------------------------------------------------------- processes
    def collect_processes(self) -> None:
        rows = ps_json(
            "Get-CimInstance Win32_Process | ForEach-Object { $o = $_.GetOwner(); [PSCustomObject]@{"
            "pid=$_.ProcessId; ppid=$_.ParentProcessId; name=$_.Name; exe=$_.ExecutablePath; cmdline=$_.CommandLine; "
            "start_time=$_.CreationDate; session=$_.SessionId; user=if($o.User){\"$($o.Domain)\\$($o.User)\"}else{''} } }")
        paths = sorted({r.get("exe") for r in rows if r.get("exe")})
        sigs: Dict[str, Dict[str, Any]] = {}
        if paths and not self.quick:
            sig_rows = ps_json("@(" + ",".join("'" + p.replace("'", "''") + "'" for p in paths[:400]) + ") | ForEach-Object { "
                               "$s = Get-AuthenticodeSignature -FilePath $_ -ErrorAction SilentlyContinue; "
                               "[PSCustomObject]@{path=$_; status=\"$($s.Status)\"; signer=$s.SignerCertificate.Subject} }", 240)
            sigs = {s["path"]: s for s in sig_rows if s.get("path")}
        hashes: Dict[str, str] = {}
        if self.hash_files and paths:
            h_rows = ps_json("@(" + ",".join("'" + p.replace("'", "''") + "'" for p in paths[:400]) + ") | ForEach-Object { "
                             "$h = Get-FileHash -Algorithm SHA256 -Path $_ -ErrorAction SilentlyContinue; "
                             "[PSCustomObject]@{path=$_; sha256=$h.Hash} }", 300)
            hashes = {h["path"]: h.get("sha256") for h in h_rows if h.get("path")}
        for r in rows:
            exe = r.get("exe") or ""
            if exe in sigs:
                r["signature"] = sigs[exe].get("status")
                r["signer"] = sigs[exe].get("signer")
            if exe in hashes:
                r["sha256"] = hashes[exe]
            if exe:
                r.update({k: v for k, v in file_times(exe).items() if k in ("mtime", "ctime", "size")})
        self.bundle.add("processes", rows)

    def collect_services(self) -> None:
        rows = ps_json("Get-CimInstance Win32_Service | Select-Object @{n='name';e={$_.Name}},@{n='display_name';e={$_.DisplayName}},"
                       "@{n='path';e={$_.PathName}},@{n='start_mode';e={$_.StartMode}},@{n='state';e={$_.State}},"
                       "@{n='account';e={$_.StartName}},@{n='pid';e={$_.ProcessId}},@{n='description';e={$_.Description}}")
        for r in rows:
            r["description"] = (r.get("description") or "")[:200]
            r["type"] = "service"
        # svchost-hosted services pointing at a ServiceDll
        dlls = ps_json("Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' | ForEach-Object { "
                       "$p = Get-ItemProperty ($_.PSPath + '\\Parameters') -ErrorAction SilentlyContinue; "
                       "if ($p.ServiceDll) { [PSCustomObject]@{name=$_.PSChildName; service_dll=$p.ServiceDll} } }", 120)
        dmap = {d["name"].lower(): d["service_dll"] for d in dlls if d.get("name")}
        for r in rows:
            if r.get("name", "").lower() in dmap:
                r["service_dll"] = dmap[r["name"].lower()]
        self.bundle.add("services", rows)

    def collect_drivers(self) -> None:
        rows = ps_json("Get-CimInstance Win32_SystemDriver | Select-Object @{n='name';e={$_.Name}},@{n='path';e={$_.PathName}},"
                       "@{n='state';e={$_.State}},@{n='start_mode';e={$_.StartMode}}")
        self.bundle.add("drivers", rows)

    # ------------------------------------------------------ scheduled tasks
    def collect_tasks(self) -> None:
        out = run(["schtasks.exe", "/query", "/fo", "CSV", "/v"], 120)
        rows: List[Dict[str, Any]] = []
        if out:
            reader = csv.DictReader(io.StringIO(out))
            for r in reader:
                if r.get("TaskName") == "TaskName":  # repeated header rows per folder
                    continue
                rows.append({
                    "name": r.get("TaskName"), "command": r.get("Task To Run"), "status": r.get("Status"),
                    "author": r.get("Author"), "run_as": r.get("Run As User"), "last_run": r.get("Last Run Time"),
                    "next_run": r.get("Next Run Time"), "schedule": r.get("Schedule Type"),
                    "logon_mode": r.get("Logon Mode"), "comment": (r.get("Comment") or "")[:200],
                })
        # Task XML files carry creation dates and the real action/args (schtasks truncates)
        for p in glob.glob(os.path.join(self.windir, "System32", "Tasks", "**", "*"), recursive=True):
            if os.path.isfile(p):
                rel = "\\" + os.path.relpath(p, os.path.join(self.windir, "System32", "Tasks"))
                for r in rows:
                    if r.get("name", "").lower() == rel.lower():
                        r.update({"xml_" + k: v for k, v in file_times(p).items() if k in ("mtime", "ctime")})
        self.bundle.add("scheduled_tasks", rows)

    # ------------------------------------------------------------ autoruns
    def collect_autoruns(self) -> None:
        keys = ",".join("'" + k + "'" for k in AUTORUN_KEYS)
        rows = ps_json(
            f"@({keys}) | ForEach-Object {{ $k = $_; $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue; "
            "if ($p) { $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { "
            "[PSCustomObject]@{key=$k; name=$_.Name; value=\"$($_.Value)\"} } } "
            "Get-ChildItem -Path $k -ErrorAction SilentlyContinue | ForEach-Object { $c = $_; "
            "$cp = Get-ItemProperty $c.PSPath -ErrorAction SilentlyContinue; if ($cp) { $cp.PSObject.Properties | "
            "Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { [PSCustomObject]@{key=($k + '\\' + $c.PSChildName); "
            "name=$_.Name; value=\"$($_.Value)\"} } } } }", 180)
        for r in rows:
            r["source"] = "registry"
            r["value"] = (r.get("value") or "")[:1000]
        # Per-user HKU hives for logged-off users
        hku = ps_json("Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.Name -match 'S-1-5-21-\\d+-\\d+-\\d+-\\d+$' } | "
                      "ForEach-Object { $sid=$_.PSChildName; foreach ($sub in @('Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
                      "'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce','Environment')) { $p = Get-ItemProperty "
                      "(\"Registry::HKEY_USERS\\$sid\\$sub\") -ErrorAction SilentlyContinue; if ($p) { $p.PSObject.Properties | "
                      "Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { [PSCustomObject]@{key=\"HKU\\$sid\\$sub\"; "
                      "name=$_.Name; value=\"$($_.Value)\"} } } } }", 120)
        for r in hku:
            r["source"] = "registry"
            rows.append(r)
        # Startup folders
        startup_dirs = [os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                     r"Microsoft\Windows\Start Menu\Programs\StartUp")]
        startup_dirs += glob.glob(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        for d in startup_dirs:
            for p in glob.glob(os.path.join(d, "*")):
                rows.append({"key": d, "name": os.path.basename(p), "value": p, "source": "startup_folder", **file_times(p)})
        self.bundle.add("autoruns", rows)

    def collect_wmi(self) -> None:
        rows = []
        for cls, kind in (("__EventFilter", "filter"), ("CommandLineEventConsumer", "consumer"),
                          ("ActiveScriptEventConsumer", "consumer"), ("__FilterToConsumerBinding", "binding")):
            items = ps_json(f"Get-CimInstance -Namespace root/subscription -ClassName {cls} -ErrorAction SilentlyContinue | "
                            "Select-Object Name,Query,CommandLineTemplate,ScriptText,ExecutablePath,Filter,Consumer")
            for it in items:
                it["kind"] = kind
                it["class"] = cls
                rows.append({k: (str(v)[:1000] if v is not None else None) for k, v in it.items()})
        self.bundle.add("wmi_subscriptions", rows)

    # ------------------------------------------------------------- network
    def collect_network(self) -> None:
        tcp = ps_json("Get-NetTCPConnection | Select-Object @{n='proto';e={'tcp'}},@{n='local_addr';e={$_.LocalAddress}},"
                      "@{n='local_port';e={$_.LocalPort}},@{n='remote_addr';e={$_.RemoteAddress}},@{n='remote_port';e={$_.RemotePort}},"
                      "@{n='state';e={\"$($_.State)\"}},@{n='pid';e={$_.OwningProcess}},@{n='created';e={$_.CreationTime}}")
        udp = ps_json("Get-NetUDPEndpoint | Select-Object @{n='proto';e={'udp'}},@{n='local_addr';e={$_.LocalAddress}},"
                      "@{n='local_port';e={$_.LocalPort}},@{n='pid';e={$_.OwningProcess}}")
        pmap = {p.get("pid"): p for p in self.bundle.get("processes")}
        rows = tcp + udp
        for r in rows:
            p = pmap.get(r.get("pid"))
            if p:
                r["process"] = p.get("name")
                r["exe"] = p.get("exe")
                r["user"] = p.get("user")
            if r["proto"] == "tcp":
                r["state"] = (r.get("state") or "").upper()
                if r["state"] == "LISTEN":
                    r["state"] = "LISTEN"
        self.bundle.add("network", rows)

    # --------------------------------------------------------------- users
    def collect_users(self) -> None:
        rows = ps_json("Get-LocalUser | Select-Object @{n='name';e={$_.Name}},@{n='enabled';e={$_.Enabled}},"
                       "@{n='last_logon';e={$_.LastLogon}},@{n='pw_last_set';e={$_.PasswordLastSet}},"
                       "@{n='sid';e={$_.SID.Value}},@{n='description';e={$_.Description}},@{n='pw_required';e={$_.PasswordRequired}}")
        admins = ps_json("Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | "
                         "Select-Object @{n='name';e={$_.Name}},@{n='class';e={$_.ObjectClass}},@{n='source';e={\"$($_.PrincipalSource)\"}}")
        rdp = ps_json("Get-LocalGroupMember -Group 'Remote Desktop Users' -ErrorAction SilentlyContinue | Select-Object @{n='name';e={$_.Name}}")
        admin_names = {a.get("name", "").lower() for a in admins}
        rdp_names = {a.get("name", "").lower() for a in rdp}
        host = socket.gethostname().lower()
        for r in rows:
            full = f"{host}\\{r.get('name','')}".lower()
            r["privileged_groups"] = (["Administrators"] if full in admin_names else []) + (["Remote Desktop Users"] if full in rdp_names else [])
            r["hidden_from_logon"] = r.get("name", "").endswith("$")
        # Non-local admins (domain accounts/groups added to local admins)
        for a in admins:
            if a.get("name", "").lower().split("\\")[0] != host:
                rows.append({"name": a.get("name"), "sid": "", "privileged_groups": ["Administrators"], "domain_principal": True,
                             "class": a.get("class"), "source": a.get("source")})
        profiles = ps_json("Get-CimInstance Win32_UserProfile | Select-Object @{n='sid';e={$_.SID}},@{n='path';e={$_.LocalPath}},"
                           "@{n='last_use';e={$_.LastUseTime}},@{n='loaded';e={$_.Loaded}}")
        self.bundle.add("users", rows)
        self.bundle.add("profiles", profiles)

    # ------------------------------------------------------------ prefetch
    def collect_prefetch(self) -> None:
        rows = []
        for p in glob.glob(os.path.join(self.windir, "Prefetch", "*.pf")):
            name = os.path.basename(p)
            rows.append({"file": name, "executable": name.rsplit("-", 1)[0], "path": p, **file_times(p)})
        rows.sort(key=lambda r: r.get("mtime") or "", reverse=True)
        self.bundle.add("prefetch", rows)

    # -------------------------------------------------------------- events
    def collect_events(self) -> None:
        rows: List[Dict[str, Any]] = []
        for channel, xpath in EVENT_QUERIES.items():
            if self.quick and channel not in ("Security", "System", "Microsoft-Windows-PowerShell/Operational",
                                              "Microsoft-Windows-Sysmon/Operational"):
                continue
            out = run(["wevtutil.exe", "qe", channel, "/q:" + xpath, "/c:" + str(self.event_limit), "/rd:true", "/f:xml"], 300)
            if not out.strip():
                continue
            recs = parse_wevtutil_xml(out, host=self.bundle.host)
            for r in recs:
                r.setdefault("channel", channel)
            rows.extend(recs)
        self.bundle.add("events", rows)

    def collect_defender(self) -> None:
        status = ps_json("Get-MpComputerStatus -ErrorAction SilentlyContinue | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
                         "IoavProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureLastUpdated,IsTamperProtected,AMServiceEnabled")
        prefs = ps_json("Get-MpPreference -ErrorAction SilentlyContinue | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension,"
                        "DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableScriptScanning,DisableIOAVProtection")
        rows = []
        if status:
            rows.append({"kind": "status", **status[0]})
        if prefs:
            rows.append({"kind": "preferences", **prefs[0]})
        self.bundle.add("defender", rows)

    def collect_pipes(self) -> None:
        out = run(PS + ["[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | ForEach-Object { $_.Substring(9) }"], 30)
        rows = [{"name": l.strip()} for l in out.splitlines() if l.strip()]
        self.bundle.add("named_pipes", rows)

    def collect_dns(self) -> None:
        cache = ps_json("Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object @{n='name';e={$_.Entry}},@{n='data';e={$_.Data}},"
                        "@{n='type';e={$_.Type}}")
        hosts_path = os.path.join(self.windir, "System32", "drivers", "etc", "hosts")
        hosts = []
        try:
            with open(hosts_path, encoding="utf-8", errors="replace") as fh:
                hosts = [l.strip() for l in fh if l.strip() and not l.strip().startswith("#")]
        except OSError:
            pass
        self.bundle.add("dns", [{"hosts": hosts, "hosts_mtime": file_times(hosts_path).get("mtime"), "cache": cache[:2000]}])

    def collect_shares(self) -> None:
        rows = ps_json("Get-SmbShare -ErrorAction SilentlyContinue | Select-Object @{n='name';e={$_.Name}},@{n='path';e={$_.Path}},"
                       "@{n='description';e={$_.Description}}")
        sessions = ps_json("Get-SmbSession -ErrorAction SilentlyContinue | Select-Object @{n='client';e={$_.ClientComputerName}},"
                           "@{n='user';e={$_.ClientUserName}},@{n='opens';e={$_.NumOpens}}")
        self.bundle.add("shares", rows)
        self.bundle.add("smb_sessions", sessions)

    def collect_recent_files(self) -> None:
        rows = []
        for d in ("Downloads", "Desktop", r"AppData\Local\Temp", r"AppData\Roaming", "Documents"):
            for p in glob.glob(rf"C:\Users\*\{d}\*"):
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                if time.time() - st.st_mtime < 30 * 86400 and os.path.isfile(p):
                    ext = os.path.splitext(p)[1].lower()
                    if ext in (".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".iso", ".img", ".lnk", ".zip",
                               ".7z", ".rar", ".scr", ".msi", ".jar", ".wsf", ".docm", ".xlsm", ".one", ".url"):
                        rec = {"path": p, "ext": ext, **file_times(p)}
                        if self.hash_files:
                            rec["sha256"] = sha256_file(p)
                        rows.append(rec)
        for p in glob.glob(r"C:\Users\Public\*") + glob.glob(r"C:\ProgramData\*.exe") + glob.glob(r"C:\PerfLogs\*") + glob.glob(r"C:\Windows\Temp\*.exe"):
            if os.path.isfile(p):
                rows.append({"path": p, "ext": os.path.splitext(p)[1].lower(), **file_times(p)})
        self.bundle.add("recent_files", rows)

    def collect_ps_history(self) -> None:
        rows = []
        for p in glob.glob(r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"):
            user = p.split("\\")[2]
            try:
                with open(p, encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, 1):
                        if line.strip():
                            rows.append({"user": user, "file": p, "line": i, "command": line.strip()[:1000],
                                         "file_mtime": file_times(p).get("mtime")})
            except OSError:
                continue
        self.bundle.add("shell_history", rows)

    def collect_firewall(self) -> None:
        profiles = ps_json("Get-NetFirewallProfile | Select-Object @{n='name';e={$_.Name}},@{n='enabled';e={$_.Enabled}}")
        rules = ps_json("Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | Where-Object { $_.Owner -or "
                        "$_.DisplayName -notmatch '^(Core Networking|File and Printer|Network Discovery|Remote |Windows|Microsoft|mDNS|"
                        "Cast to|Delivery|AllJoyn|Wi-Fi|Wireless|Start|Cortana|Your Phone|Xbox|Connected)' } | "
                        "Select-Object @{n='name';e={$_.DisplayName}},@{n='profile';e={\"$($_.Profile)\"}},"
                        "@{n='program';e={($_ | Get-NetFirewallApplicationFilter).Program}},"
                        "@{n='port';e={($_ | Get-NetFirewallPortFilter).LocalPort}}", 180)
        self.bundle.add("firewall", [{"kind": "profile", **p} for p in profiles] + [{"kind": "rule", **r} for r in rules[:300]])
