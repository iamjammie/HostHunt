"""Shared detection vocabulary for the rule engine.

These are matchers a SIEM/EDR analyst would recognise: known paths that user-land
malware tends to live in, system binaries that have a fixed legitimate home, and
command-line signatures drawn from the public LOLBAS/GTFOBins project and ATT&CK.
Everything here is used only to *flag artefacts for a responder to review* — the
tool neither executes nor explains how to carry out any of the referenced techniques.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------- Windows paths
WIN_SUSPICIOUS_DIR = re.compile(
    r"(\\users\\[^\\]+\\appdata\\local\\temp\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\users\\public\\|"
    r"\\\$recycle\.bin\\|\\perflogs\\|\\windows\\tasks\\|\\windows\\debug\\|\\windows\\fonts\\|"
    r"\\windows\\help\\|\\windows\\tracing\\|\\windows\\system32\\spool\\drivers\\color\\|"
    r"\\users\\[^\\]+\\downloads\\|\\users\\[^\\]+\\desktop\\|\\users\\[^\\]+\\music\\|"
    r"\\users\\[^\\]+\\videos\\|\\users\\[^\\]+\\pictures\\|\\recovery\\|\\users\\default\\|"
    r"\\intel\\|\\windows\\installer\\)", re.I)

WIN_SYSTEM_DIR = re.compile(r"^[a-z]:\\windows\\(system32|syswow64|winsxs|servicing|microsoft\.net)\\", re.I)
WIN_PROGRAM_DIR = re.compile(r"^[a-z]:\\(program files( \(x86\))?|windows|programdata\\microsoft)\\", re.I)

# System binaries whose only legitimate home is %SystemRoot%\System32 / SysWOW64
WIN_SYSTEM_BINARIES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "dllhost.exe",
    "lsm.exe", "wmiprvse.exe", "searchindexer.exe", "ctfmon.exe", "sihost.exe", "fontdrvhost.exe",
}
# Child process -> set of parents that are normal for it. A mismatch is worth a look.
WIN_EXPECTED_PARENT = {
    "svchost.exe": {"services.exe", "msmpeng.exe"},
    "lsass.exe": {"wininit.exe"},
    "services.exe": {"wininit.exe"},
    "csrss.exe": {"smss.exe"},
    "winlogon.exe": {"smss.exe"},
    "wininit.exe": {"smss.exe"},
    "smss.exe": {"system", "smss.exe"},
    "taskhostw.exe": {"svchost.exe"},
    "spoolsv.exe": {"services.exe"},
    "runtimebroker.exe": {"svchost.exe"},
    "dwm.exe": {"winlogon.exe"},
    "userinit.exe": {"winlogon.exe"},
}
# Lookalike spellings of system binaries (masquerading).
WIN_LOOKALIKES = re.compile(r"^(svch0st|scvhost|svhost|svchosts|lsasss|lsas|csrs|csrsss|exp1orer|explore|wininlt|"
                            r"win1ogon|taskhosts|taskmgrs|rundl132|rund1l32|spools|conhosts|dllhosts|chrome32|"
                            r"svchost32|lsass32|msmpeng32|wmiprvse32|services32|csrss32)\.exe$", re.I)

OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "onenote.exe", "visio.exe", "mspub.exe"}
SHELLS_AND_SCRIPT_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
                           "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "wmic.exe", "schtasks.exe",
                           "curl.exe", "bash.exe", "hh.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                           "cmstp.exe", "forfiles.exe", "scrcons.exe", "odbcconf.exe", "control.exe"}
BROWSERS_AND_READERS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "acrord32.exe", "acrobat.exe",
                        "foxitreader.exe", "teams.exe", "slack.exe", "thunderbird.exe"}

# LOLBin command-line signatures: (regex, short label, ATT&CK technique id). Used to
# surface a process/command for analyst review, mapped to the technique for context.
LOLBIN_PATTERNS = [
    (r"\bmshta(\.exe)?\b.*(http|javascript:|vbscript:|\.hta)", "mshta remote/inline script", "T1218.005"),
    (r"\bregsvr32(\.exe)?\b.*(/i:|-i:|scrobj\.dll|http)", "regsvr32 scriptlet load", "T1218.010"),
    (r"\brundll32(\.exe)?\b.*(javascript:|url\.dll|,#?\d+\s*$|advpack|ieadvpack|\\temp\\|\\appdata\\)", "rundll32 proxy load", "T1218.011"),
    (r"\bcertutil(\.exe)?\b.*(-urlcache|-decode|-encode|-split|-verifyctl|-addstore)", "certutil transfer/decode", "T1140"),
    (r"\bbitsadmin(\.exe)?\b.*(/transfer|/addfile|/create|/setnotifycmdline)", "bitsadmin transfer", "T1197"),
    (r"\bmsiexec(\.exe)?\b.*(/q.*http|http.*/q)", "msiexec remote package", "T1218.007"),
    (r"\bwmic(\.exe)?\b.*(process call create|/node:|shadowcopy delete|os get /format)", "wmic exec/remote", "T1047"),
    (r"\bcmstp(\.exe)?\b.*(/s|/ns).*\.inf", "cmstp inf execution", "T1218.003"),
    (r"\b(msbuild|installutil|regasm|regsvcs)(\.exe)?\b.*\.(xml|csproj|proj|dll|exe)", "dotnet build-tool execution", "T1127.001"),
    (r"\bodbcconf(\.exe)?\b.*(/a|regsvr)", "odbcconf dll load", "T1218.008"),
    (r"\bcontrol(\.exe)?\b.*\.cpl", "control.exe cpl load", "T1218.002"),
    (r"\bforfiles(\.exe)?\b.*/c\s", "forfiles proxy execution", "T1202"),
    (r"\bvssadmin(\.exe)?\b.*delete shadows|\bwbadmin(\.exe)?\b.*delete|\bbcdedit\b.*(recoveryenabled no|ignoreallfailures)", "backup/recovery tampering", "T1490"),
    (r"\bcurl(\.exe)?\b.*(-o |--output|-O )|\bInvoke-WebRequest\b|\bwget\b.*http|\bStart-BitsTransfer\b", "command-line downloader", "T1105"),
    (r"\bnetsh\b.*(advfirewall set .*state off|firewall set opmode disable|portproxy add|wlan show profile.*key=clear)", "netsh firewall/portproxy change", "T1562.004"),
    (r"\bsc(\.exe)?\b\s+(\\\\\S+\s+)?(create|config)\b.*binpath", "service create/config", "T1543.003"),
    (r"\bschtasks(\.exe)?\b.*/create\b", "scheduled task create", "T1053.005"),
    (r"\breg(\.exe)?\b\s+(add|save)\b.*(\\run\b|currentversion\\run|hklm\\sam|hklm\\system|hklm\\security|disableantispyware|enablelua|userinit|image file execution)", "registry persistence / hive access", "T1112"),
    (r"\bnet(1)?(\.exe)?\s+(user|localgroup)\b.*(/add|administrators)", "local account/group change", "T1136.001"),
]

# PowerShell command-line / script-block signatures.
PS_SUSPICIOUS = [
    (r"(^|\s)-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "encoded command", "T1027.010"),
    (r"frombase64string|-bxor|\[char\]\d+\s*\+|\[string\]::join|-join\s*\(", "obfuscation primitives", "T1027"),
    (r"(iex|invoke-expression)\b.*(downloadstring|downloadfile|webclient|invoke-webrequest|iwr|net\.webclient)", "download-and-run cradle", "T1059.001"),
    (r"(downloadstring|downloadfile|downloaddata)\(", "webclient download", "T1105"),
    (r"-nop\b|-noni\b|-w\s+hidden|-windowstyle\s+hidden|-exec(utionpolicy)?\s+bypass", "stealth launch flags", "T1059.001"),
    (r"\[reflection\.assembly\]::load|\[system\.reflection\.assembly\]::load|loadwithpartialname", "reflective assembly load", "T1620"),
    (r"virtualalloc|writeprocessmemory|createremotethread|ntmapviewofsection|rtlmovememory|getdelegatefortype", "in-memory injection api", "T1055"),
    (r"get-wmiobject.*win32_|invoke-wmimethod|invoke-cimmethod.*create", "wmi via powershell", "T1047"),
    (r"invoke-mimikatz|invoke-kerberoast|invoke-dcsync|rubeus|sharphound|bloodhound|powerview|powersploit|nishang|invoke-shellcode|invoke-dllinjection", "known offensive toolkit name", "T1588.002"),
    (r"new-object\s+net\.sockets\.tcpclient|\$client\s*=\s*new-object\s+system\.net\.sockets", "reverse shell primitive", "T1059.001"),
    (r"set-mppreference.*-disable|add-mppreference.*exclusion", "defender tampering", "T1562.001"),
]

# Linux shell command signatures.
NIX_SUSPICIOUS = [
    (r"\b(curl|wget)\b.*\|\s*(bash|sh|python|perl)\b", "download piped to interpreter", "T1059.004"),
    (r"\bbash\s+-i\b|\b(sh|bash)\s+-i\b.*(>&|<>)\s*/dev/tcp/|/dev/tcp/\d|/dev/udp/", "reverse shell", "T1059.004"),
    (r"\bnc\b.*(-e|-c)\b|\bncat\b.*(-e|--exec)|\bmkfifo\b.*\|\s*(nc|bash)", "netcat/named-pipe shell", "T1059.004"),
    (r"\bpython[0-9.]*\s+-c\b.*(socket|pty\.spawn|os\.system|subprocess)", "python inline shell/socket", "T1059.006"),
    (r"\bchmod\s+(\+x|[0-7]*7[0-7]*)\b.*(/tmp/|/dev/shm/|/var/tmp/|\./)", "make dropped file executable", "T1222.002"),
    (r"\bbase64\s+-d\b|\becho\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64", "base64 decode payload", "T1140"),
    (r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|export\s+HISTFILE=/dev/null|\bln\s+-sf\s+/dev/null.*history|set \+o history", "shell history tampering", "T1070.003"),
    (r"\b(useradd|adduser|usermod)\b.*(-u\s*0|-o\b|-g\s*0|sudo|wheel|-aG)", "privileged account change", "T1136.001"),
    (r"\bcrontab\s+(-|\S+)|/etc/cron|/var/spool/cron", "cron modification", "T1053.003"),
    (r"\bLD_PRELOAD=|/etc/ld\.so\.preload|setcap\b|\bsetuid\b", "preload / capability abuse", "T1574.006"),
    (r"\b(insmod|modprobe|kextload)\b", "kernel module load", "T1547.006"),
    (r"\b(iptables|nft).*(flush|-F|drop)|\bufw\s+disable|systemctl\s+stop\s+(auditd|rsyslog|falcon-sensor|crowdstrike)", "logging/firewall tampering", "T1562.004"),
    (r"\b(shred|srm|wipe)\b|\brm\s+-rf\s+(/|~|/\*|/root|/home|/var/log)|>\s*/var/log/", "log/file destruction", "T1070"),
    (r"\bdd\b.*if=.*of=/dev/(sd|nvme|xvd)|mkfs\.", "disk wipe", "T1561"),
    (r"\b(scp|rsync|sftp)\b.*@|\bcurl\b.*(-T|--upload-file|-F )|\btar\b.*\|\s*(nc|ssh|curl)", "possible exfil channel", "T1048"),
    (r"nohup\b.*&\s*$|setsid\b|disown\b|&\s*disown", "process detachment", "T1059.004"),
    (r"\b(gcc|cc)\b.*\.c\b.*-o\s|/tmp/.*\.c\b", "on-host compilation", "T1587.001"),
    (r"xmrig|minerd|stratum\+tcp|--donate-level|cryptonight|nanopool|supportxmr|moneroocean", "coin miner indicator", "T1496"),
]

# C2 / download URL indicators worth surfacing regardless of context.
SUSPICIOUS_URL = re.compile(r"(\b(?:\d{1,3}\.){3}\d{1,3}\b(?::\d+)?/|\.onion\b|pastebin\.com/raw|raw\.githubusercontent|"
                            r"transfer\.sh|discord(app)?\.com/api/webhooks|t\.me/|ngrok\.|trycloudflare\.com|"
                            r"\.workers\.dev|anonfiles|mega\.nz|temp\.sh|0x0\.st|bashupload|file\.io|dpaste|termbin)", re.I)

# Ports frequently used by remote-access / C2 tooling (context, not verdict).
NOTABLE_PORTS = {4444: "metasploit default", 1080: "socks proxy", 5555: "adb/common backdoor",
                 6667: "irc c2", 6697: "irc c2 tls", 8080: "http alt/proxy", 9001: "tor orport",
                 9050: "tor socks", 1337: "common backdoor", 31337: "elite backdoor", 12345: "netbus",
                 5900: "vnc", 3389: "rdp", 2222: "alt ssh", 4443: "c2 https alt", 8443: "https alt",
                 50050: "cobalt strike teamserver default", 443: "", 8888: "http alt"}


def hits(patterns, text):
    """Yield (label, technique) for every pattern that matches ``text``."""
    if not text:
        return
    for rx, label, tech in patterns:
        if re.search(rx, text, re.I):
            yield label, tech
