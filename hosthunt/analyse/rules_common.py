"""Platform-agnostic rules: network, shell history, cross-artefact correlation."""
from __future__ import annotations

from typing import Dict, Iterable

from ..models import Bundle
from ..util import lower, parse_ts
from .engine import rule
from . import patterns as P


@rule("NET-001", "Outbound connection to notable C2/backdoor port", "medium", "network",
      technique="T1571", tactic="Command and Control",
      description="A process holds a connection to a port commonly associated with remote-access or C2 tooling.",
      recommendation="Pivot on the remote IP, the owning process and its parent. Confirm against known-good baselines.")
def net_notable_port(b: Bundle) -> Iterable[Dict]:
    for c in b.get("network"):
        state = lower(c.get("state"))
        if state and state not in ("established", "syn_sent"):
            continue
        rp = c.get("remote_port")
        ra = str(c.get("remote_addr") or "")
        if ra in ("0.0.0.0", "::", "", "127.0.0.1", "::1"):
            continue
        try:
            rp = int(rp)
        except (TypeError, ValueError):
            continue
        if rp in P.NOTABLE_PORTS and P.NOTABLE_PORTS[rp]:
            yield {"remote": f"{ra}:{rp}", "note": P.NOTABLE_PORTS[rp], "process": c.get("process"),
                   "pid": c.get("pid"), "exe": c.get("exe"), "user": c.get("user"), "state": c.get("state"),
                   "_severity": "high" if rp in (4444, 50050, 1337, 31337) else "medium",
                   "_tags": ["c2-port"]}


@rule("NET-002", "Listening service on an unusual high port", "low", "network",
      technique="T1571", tactic="Command and Control",
      description="A process is listening for inbound connections on a high/ephemeral port, which can indicate a backdoor or tunnel.",
      recommendation="Validate the listener is an expected service. Unknown listeners owned by user processes warrant triage.")
def net_listener(b: Bundle) -> Iterable[Dict]:
    for c in b.get("network"):
        if lower(c.get("state")) != "listen":
            continue
        try:
            lp = int(c.get("local_port"))
        except (TypeError, ValueError):
            continue
        exe = lower(c.get("exe"))
        if lp >= 1024 and lp not in (3306, 5432, 6379, 27017, 8000, 8080, 8443, 9090, 5000, 3000):
            if lp in P.NOTABLE_PORTS and P.NOTABLE_PORTS[lp]:
                yield {"local_port": lp, "process": c.get("process"), "pid": c.get("pid"), "exe": c.get("exe"),
                       "note": P.NOTABLE_PORTS[lp], "_severity": "medium", "_tags": ["suspicious-listener"]}
            elif exe and (P.WIN_SUSPICIOUS_DIR.search(exe) or "/tmp/" in exe or "/dev/shm" in exe):
                yield {"local_port": lp, "process": c.get("process"), "pid": c.get("pid"), "exe": c.get("exe"),
                       "note": "listener running from a temp/suspicious path", "_severity": "high"}


@rule("HIST-001", "Suspicious command in shell history", "medium", "shell_history",
      technique="T1059", tactic="Execution",
      description="A recorded shell/PowerShell history entry matches a known attacker command pattern.",
      recommendation="Correlate the timestamp with logins and process creation to establish who ran it and what followed.")
def hist_suspicious(b: Bundle) -> Iterable[Dict]:
    plat = b.platform
    pats = P.PS_SUSPICIOUS if plat == "windows" else P.NIX_SUSPICIOUS
    for h in b.get("shell_history"):
        cmd = h.get("command") or ""
        if not cmd:
            continue
        labels = list(P.hits(pats, cmd))
        urlhit = bool(P.SUSPICIOUS_URL.search(cmd))
        if not labels and not urlhit:
            continue
        techs = sorted({t for _, t in labels})
        names = sorted({n for n, _ in labels})
        if urlhit:
            names.append("suspicious url/host")
        sev = "high" if any(n in ("known offensive toolkit name", "reverse shell", "reverse shell primitive",
                                   "download-and-run cradle", "download piped to interpreter", "coin miner indicator",
                                   "defender tampering") for n in names) else "medium"
        yield {"user": h.get("user"), "command": cmd[:500], "matched": names, "techniques": techs,
               "file": h.get("file"), "line": h.get("line"), "_timestamp": h.get("timestamp"),
               "_severity": sev, "_tags": ["shell-history"],
               "_description": "History entry matched: " + ", ".join(names)}


@rule("HIST-002", "History file truncated, missing, or cleared", "low", "shell_history",
      technique="T1070.003", tactic="Defense Evasion",
      description="A shell history file is empty or symlinked away, which can indicate anti-forensic clearing.",
      recommendation="Compare against expected activity for the account; an interactive account with no history is suspicious.")
def hist_cleared(b: Bundle) -> Iterable[Dict]:
    if b.platform == "windows":
        return
    seen_users = {}
    for h in b.get("shell_history"):
        seen_users.setdefault(h.get("user"), 0)
        seen_users[h.get("user")] += 1
    for u in b.get("users"):
        shell = lower(u.get("shell"))
        name = u.get("name")
        if shell and not shell.endswith(("nologin", "false", "sync", "halt")) and u.get("home", "").startswith(("/home", "/root")):
            if seen_users.get(name, 0) == 0:
                yield {"user": name, "home": u.get("home"), "shell": u.get("shell"),
                       "note": "interactive account has no readable shell history", "_severity": "low",
                       "_tags": ["anti-forensics"]}


@rule("DNS-001", "Hosts file contains redirect or injected entry", "medium", "dns",
      technique="T1565.001", tactic="Impact",
      description="The hosts file maps hostnames to IPs, which attackers use to redirect update/security traffic or pin C2.",
      recommendation="Review each non-default mapping. Redirects of vendor/update domains to private IPs are high priority.")
def dns_hosts(b: Bundle) -> Iterable[Dict]:
    for d in b.get("dns"):
        for line in d.get("hosts", []):
            low = lower(line)
            if any(k in low for k in ("update", "windowsupdate", "microsoft", "sophos", "mcafee", "symantec",
                                      "crowdstrike", "defender", "clamav", "google", "apple", "ubuntu", "debian",
                                      "redhat", "security", "antivirus", "sentinelone")):
                yield {"entry": line.strip(), "note": "hosts entry references a vendor/update domain",
                       "mtime": d.get("hosts_mtime"), "_severity": "high", "_tags": ["hosts-hijack"]}
            elif line.strip() and not line.strip().startswith(("127.0.0.1", "::1", "255.255.255.255", "fe00::", "ff00::", "ff02::")):
                yield {"entry": line.strip(), "note": "non-default hosts mapping", "mtime": d.get("hosts_mtime"),
                       "_severity": "low", "_tags": ["hosts-entry"]}
