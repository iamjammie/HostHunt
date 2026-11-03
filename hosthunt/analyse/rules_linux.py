"""Linux-specific detection rules."""
from __future__ import annotations

import re
from typing import Dict, Iterable

from ..models import Bundle
from ..util import lower
from .engine import rule
from . import patterns as P

NIX_SUSPICIOUS_DIR = re.compile(r"(^|/)(tmp|var/tmp|dev/shm|run/shm|var/run|run/user/\d+|\.cache|\.config/\.|"
                                r"var/spool|srv/\.|home/[^/]+/\.[^/]+)/", re.I)
TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/")


# ----------------------------------------------------------------- processes
@rule("NIX-PROC-001", "Process running from a temporary/world-writable path", "high", "processes",
      technique="T1036", tactic="Defense Evasion", platform="linux",
      description="An executing image lives under /tmp, /dev/shm, or another world-writable location often used for staging.",
      recommendation="Hash the image and review its parent; legitimate daemons rarely execute from temp directories.")
def nix_proc_tmp(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        exe = p.get("exe") or ""
        if exe.startswith(TEMP_PREFIXES):
            yield {"process": p.get("name"), "pid": p.get("pid"), "exe": exe, "cmdline": (p.get("cmdline") or "")[:400],
                   "user": p.get("user"), "cwd": p.get("cwd"), "sha256": p.get("sha256"),
                   "_timestamp": p.get("start_time"), "_tags": ["temp-exec"]}


@rule("NIX-PROC-002", "Process image deleted from disk while running", "high", "processes",
      technique="T1070.004", tactic="Defense Evasion", platform="linux",
      description="The running executable (or a mapped library) has been unlinked from disk — common for fileless or self-deleting malware.",
      recommendation="Dump the process memory/maps before termination; a deleted-but-running image is rarely benign on a server.")
def nix_proc_deleted(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        exe = p.get("exe") or ""
        deleted = p.get("deleted_maps") or []
        if "(deleted)" in exe or "memfd:" in exe:
            yield {"process": p.get("name"), "pid": p.get("pid"), "exe": exe, "cmdline": (p.get("cmdline") or "")[:400],
                   "user": p.get("user"), "_timestamp": p.get("start_time"), "_severity": "high", "_tags": ["deleted-binary"]}
        elif deleted:
            yield {"process": p.get("name"), "pid": p.get("pid"), "exe": exe, "deleted_maps": deleted[:5],
                   "user": p.get("user"), "_timestamp": p.get("start_time"), "_severity": "medium",
                   "_tags": ["deleted-mapping"], "_title": "Process has deleted mapped files"}


@rule("NIX-PROC-003", "Process command line matches an attacker pattern", "high", "processes",
      technique="T1059.004", tactic="Execution", platform="linux",
      description="A process command line matches a reverse-shell, downloader, miner, or tampering signature.",
      recommendation="Map the signature to its technique and reconstruct the full invocation from the parent chain.")
def nix_proc_cmd(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        cmd = p.get("cmdline") or ""
        labels = list(P.hits(P.NIX_SUSPICIOUS, cmd))
        urlhit = bool(P.SUSPICIOUS_URL.search(cmd))
        if not labels and not urlhit:
            continue
        names = sorted({n for n, _ in labels})
        techs = sorted({t for _, t in labels})
        if urlhit:
            names.append("suspicious url/host")
        sev = "critical" if "coin miner indicator" in names else ("high" if any(
            n in ("reverse shell", "netcat/named-pipe shell", "download piped to interpreter", "disk wipe",
                  "log/file destruction") for n in names) else "high")
        yield {"process": p.get("name"), "pid": p.get("pid"), "cmdline": cmd[:500], "matched": names,
               "techniques": techs, "user": p.get("user"), "_timestamp": p.get("start_time"), "_severity": sev,
               "_description": "Command line matched: " + ", ".join(names), "_tags": ["suspicious-cmd"]}


@rule("NIX-PROC-004", "Interactive process masquerading as a kernel thread", "high", "processes",
      technique="T1036.004", tactic="Defense Evasion", platform="linux",
      description="A process uses a kernel-thread-style name (e.g. [kworker]) but has a real executable path or arguments.",
      recommendation="Genuine kernel threads have no exe link and no cmdline; a bracketed name with a real image is a masquerade.")
def nix_kthread_masq(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        name = p.get("name") or ""
        cmd = p.get("cmdline") or ""
        exe = p.get("exe") or ""
        looks_kernel = (name.startswith("[") and name.endswith("]")) or (cmd.startswith("[") and cmd.endswith("]"))
        has_real_image = exe.startswith("/") and "No such" not in exe and "Permission" not in exe
        if looks_kernel and (has_real_image or (cmd and not cmd.startswith("["))):
            yield {"process": name, "pid": p.get("pid"), "exe": exe, "cmdline": cmd[:300], "user": p.get("user"),
                   "_timestamp": p.get("start_time"), "_tags": ["kthread-masquerade"]}


@rule("NIX-PROC-005", "Suspicious environment variable on a running process", "medium", "processes",
      technique="T1574.006", tactic="Persistence", platform="linux",
      description="A process runs with LD_PRELOAD / BASH_ENV / PROMPT_COMMAND set, which can hijack library loads or shell init.",
      recommendation="LD_PRELOAD pointing at a non-package .so, or a PROMPT_COMMAND that runs a payload, is high priority.")
def nix_proc_env(b: Bundle) -> Iterable[Dict]:
    for p in b.get("processes"):
        env = p.get("env") or {}
        for k in ("LD_PRELOAD", "BASH_ENV", "PROMPT_COMMAND"):
            if env.get(k):
                yield {"process": p.get("name"), "pid": p.get("pid"), "variable": k, "value": env[k][:300],
                       "user": p.get("user"), "_severity": "high" if k == "LD_PRELOAD" else "medium",
                       "_timestamp": p.get("start_time"), "_tags": ["env-hijack"]}


# ------------------------------------------------------------------ services
@rule("NIX-SVC-001", "systemd unit executes a suspicious command or temp path", "high", "services",
      technique="T1543.002", tactic="Persistence", platform="linux",
      description="A systemd service/timer ExecStart points at a temp path, an interpreter cradle, or a known attacker pattern.",
      recommendation="Review the unit file's mtime and location; units in /etc with recent mtimes deserve scrutiny.")
def nix_svc(b: Bundle) -> Iterable[Dict]:
    for s in b.get("services"):
        execs = []
        for key in ("ExecStart", "ExecStartPre", "ExecStartPost"):
            v = s.get(key)
            if isinstance(v, list):
                execs.extend(v)
            elif v:
                execs.append(v)
        joined = " ".join(execs)
        if not joined:
            continue
        labels = [n for n, _ in P.hits(P.NIX_SUSPICIOUS, joined)]
        urlhit = bool(P.SUSPICIOUS_URL.search(joined))
        temp = joined.startswith(TEMP_PREFIXES) or any(t in joined for t in TEMP_PREFIXES)
        if labels or urlhit or temp:
            yield {"unit": s.get("name"), "path": s.get("path"), "exec": joined[:500], "user": s.get("User"),
                   "matched": labels, "unit_mtime": s.get("mtime"), "enabled": s.get("enabled"),
                   "_severity": "high", "_tags": ["systemd-persistence"]}


# ---------------------------------------------------------------------- cron
@rule("NIX-CRON-001", "Cron/at job runs a suspicious command", "high", "cron",
      technique="T1053.003", tactic="Persistence", platform="linux",
      description="A cron, cron.d, or at job invokes a downloader, reverse shell, interpreter cradle, or temp-path binary.",
      recommendation="Cron is a top-three Linux persistence location; confirm the owning user and the job's edit time.")
def nix_cron(b: Bundle) -> Iterable[Dict]:
    for c in b.get("cron"):
        cmd = (c.get("command") or "") + " " + (c.get("snippet") or "")
        labels = [n for n, _ in P.hits(P.NIX_SUSPICIOUS, cmd)]
        urlhit = bool(P.SUSPICIOUS_URL.search(cmd))
        temp = any(t in cmd for t in TEMP_PREFIXES)
        interp_pipe = bool(re.search(r"(curl|wget).*(\||;|&&).*(sh|bash|python)", cmd))
        if labels or urlhit or temp or interp_pipe:
            yield {"file": c.get("file"), "schedule": c.get("schedule"), "user": c.get("user"), "command": cmd.strip()[:500],
                   "matched": labels, "mtime": c.get("mtime"), "source": c.get("source"),
                   "_severity": "high", "_tags": ["cron-persistence"]}


# ------------------------------------------------------------------ autoruns
@rule("NIX-AUTO-001", "Shell/profile init script contains a suspicious line", "high", "autoruns",
      technique="T1546.004", tactic="Persistence", platform="linux",
      description="A profile/rc/autostart file contains a downloader, reverse shell, or obfuscated line that runs on login/boot.",
      recommendation="Login persistence hides in .bashrc/.profile/profile.d; review the matched line and the file owner.")
def nix_autorun(b: Bundle) -> Iterable[Dict]:
    for a in b.get("autoruns"):
        for line in a.get("lines", []):
            labels = [n for n, _ in P.hits(P.NIX_SUSPICIOUS, line)]
            urlhit = bool(P.SUSPICIOUS_URL.search(line))
            if labels or urlhit:
                yield {"path": a.get("path"), "owner": a.get("owner_home"), "line": line[:400], "matched": labels,
                       "mtime": a.get("mtime"), "_severity": "high", "_tags": ["login-persistence"]}
        if a.get("path") == "/etc/ld.so.preload" and a.get("content"):
            yield {"path": a.get("path"), "content": a.get("content")[:400], "mtime": a.get("mtime"),
                   "_severity": "critical", "_tags": ["ld-preload"],
                   "_title": "/etc/ld.so.preload is populated (global library injection)",
                   "_description": "A populated ld.so.preload forces a library into every dynamically-linked process."}


# ------------------------------------------------------------------- ssh
@rule("NIX-SSH-001", "SSH authorized_keys entry with command/options or recent mtime", "medium", "ssh",
      technique="T1098.004", tactic="Persistence", platform="linux",
      description="An authorized_keys entry grants key-based access; forced-command/tunnel options or a recent mtime can indicate a planted key.",
      recommendation="Validate every authorized key against the user's known keys; unexplained keys are a persistence vector.")
def nix_ssh_keys(b: Bundle) -> Iterable[Dict]:
    for s in b.get("ssh"):
        if s.get("record") != "authorized_key":
            continue
        opts = s.get("options") or ""
        risky_opt = bool(re.search(r"command=|permitopen|port-forwarding|no-pty|tunnel=", opts, re.I))
        yield {"user": s.get("user"), "key_type": s.get("key_type"), "comment": s.get("comment"),
               "options": opts[:200], "file": s.get("file"), "mtime": s.get("mtime"),
               "_severity": "high" if risky_opt else "low", "_timestamp": s.get("mtime"),
               "_tags": ["ssh-key"] + (["forced-command"] if risky_opt else [])}


@rule("NIX-SSH-002", "Risky sshd_config setting", "medium", "ssh",
      technique="T1098", tactic="Persistence", platform="linux",
      description="sshd is configured to allow root login, empty passwords, or an AuthorizedKeysCommand that could be abused.",
      recommendation="Confirm these settings are intentional policy; AuthorizedKeysCommand pointing at a user path is notable.")
def nix_sshd(b: Bundle) -> Iterable[Dict]:
    for s in b.get("ssh"):
        if s.get("record") != "sshd_config":
            continue
        st = s.get("settings") or {}
        if lower(st.get("PermitRootLogin")) in ("yes", "prohibit-password", "without-password"):
            yield {"setting": "PermitRootLogin", "value": st.get("PermitRootLogin"), "file": s.get("file"),
                   "_severity": "medium", "_tags": ["sshd-config"]}
        if lower(st.get("PermitEmptyPasswords")) == "yes":
            yield {"setting": "PermitEmptyPasswords", "value": "yes", "file": s.get("file"), "_severity": "high",
                   "_tags": ["sshd-config"]}
        if st.get("AuthorizedKeysCommand"):
            yield {"setting": "AuthorizedKeysCommand", "value": st.get("AuthorizedKeysCommand"), "file": s.get("file"),
                   "_severity": "medium", "_tags": ["sshd-config"]}


# ------------------------------------------------------------------- users
@rule("NIX-USR-001", "Non-root account with UID 0", "critical", "users",
      technique="T1548", tactic="Privilege Escalation", platform="linux",
      description="An account other than root has UID 0, granting full root privilege — a classic backdoor.",
      recommendation="Any UID 0 account besides root should be treated as a backdoor and disabled after investigation.")
def nix_uid0(b: Bundle) -> Iterable[Dict]:
    for u in b.get("users"):
        if u.get("uid") == 0 and u.get("name") != "root":
            yield {"name": u.get("name"), "uid": 0, "shell": u.get("shell"), "home": u.get("home"),
                   "_severity": "critical", "_tags": ["uid0-backdoor"]}


@rule("NIX-USR-002", "Account with empty password or UID 0 group membership", "high", "users",
      technique="T1136.001", tactic="Persistence", platform="linux",
      description="An account has an empty password field or belongs to a privilege-granting group (sudo/wheel/docker).",
      recommendation="Empty-password interactive accounts and unexpected sudo/docker members are persistence/escalation risks.")
def nix_user_risk(b: Bundle) -> Iterable[Dict]:
    for u in b.get("users"):
        if u.get("name") == "root":
            continue
        if u.get("password") == "EMPTY" and not lower(u.get("shell")).endswith(("nologin", "false")):
            yield {"name": u.get("name"), "issue": "empty password", "shell": u.get("shell"), "_severity": "high",
                   "_tags": ["empty-password"]}
        priv = set(u.get("privileged_groups") or [])
        if priv & {"docker", "lxd"}:
            yield {"name": u.get("name"), "issue": "member of container group (root-equivalent)",
                   "groups": sorted(priv), "_severity": "medium", "_tags": ["docker-group"],
                   "_title": "User in root-equivalent container group"}


@rule("NIX-SUDO-001", "Dangerous sudoers rule", "high", "sudoers",
      technique="T1548.003", tactic="Privilege Escalation", platform="linux",
      description="A sudoers rule grants NOPASSWD ALL, a wildcard command, or sudo rights to an unexpected principal.",
      recommendation="NOPASSWD: ALL and wildcarded commands are common privilege-escalation footholds; confirm against policy.")
def nix_sudoers(b: Bundle) -> Iterable[Dict]:
    for s in b.get("sudoers"):
        for r in s.get("rules", []):
            low = r.lower()
            if "nopasswd" in low and "all" in low:
                yield {"file": s.get("file"), "rule": r[:300], "note": "NOPASSWD ALL", "_severity": "high",
                       "_tags": ["sudoers"]}
            elif re.search(r"=\s*\(.*\)\s*.*\*", r) or low.endswith("*"):
                yield {"file": s.get("file"), "rule": r[:300], "note": "wildcard command", "_severity": "medium",
                       "_tags": ["sudoers"]}


# ----------------------------------------------------------------- modules
@rule("NIX-MOD-001", "Loaded kernel module not present in the modules directory", "high", "modules",
      technique="T1547.006", tactic="Persistence", platform="linux",
      description="A loaded module has no matching file under /lib/modules, which can indicate an out-of-tree rootkit LKM.",
      recommendation="Compare loaded modules to the distribution's module set; an unknown module warrants memory forensics.")
def nix_modules(b: Bundle) -> Iterable[Dict]:
    for m in b.get("modules"):
        if m.get("in_modules_dir") is False:
            yield {"module": m.get("name"), "size": m.get("size"), "used_by": m.get("used_by"),
                   "_severity": "high", "_tags": ["unknown-lkm"]}


@rule("NIX-MOD-002", "Kernel reports a taint flag", "low", "modules",
      technique="T1547.006", tactic="Persistence", platform="linux",
      description="The kernel taint value is non-zero, which can reflect an out-of-tree or unsigned module being loaded.",
      recommendation="Benign for many driver setups; combine with NIX-MOD-001 to decide whether a rootkit LKM is likely.")
def nix_taint(b: Bundle) -> Iterable[Dict]:
    t = b.meta.get("kernel_tainted")
    try:
        if t and int(t) != 0:
            yield {"tainted": t, "_severity": "low", "_tags": ["kernel-taint"]}
    except (TypeError, ValueError):
        return


# ------------------------------------------------------------------- suid
@rule("NIX-SUID-001", "SUID/SGID binary in an unusual location", "high", "suid",
      technique="T1548.001", tactic="Privilege Escalation", platform="linux",
      description="A setuid/setgid binary lives outside the standard system directories, or is an interpreter/shell that grants easy escalation.",
      recommendation="SUID binaries in /tmp, /home, or SUID shells/interpreters are strong privilege-escalation indicators.")
def nix_suid(b: Bundle) -> Iterable[Dict]:
    std = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/", "/opt/")
    gtfo = {"bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby", "php", "lua", "awk", "gawk",
            "nmap", "vim", "vi", "nano", "find", "cp", "mv", "tar", "env", "nc", "socat"}
    for s in b.get("suid"):
        path = s.get("path") or ""
        name = path.rsplit("/", 1)[-1]
        in_tmp = path.startswith(TEMP_PREFIXES) or "/home/" in path or "/dev/shm" in path
        is_gtfo = name in gtfo
        if in_tmp or (is_gtfo and not path.startswith(("/usr/bin/sudo",))):
            yield {"path": path, "owner": s.get("owner"), "mode": s.get("mode"), "mtime": s.get("mtime"),
                   "note": ("in writable/home path" if in_tmp else "SUID interpreter/shell (easy escalation)"),
                   "_severity": "critical" if in_tmp else "high", "_timestamp": s.get("mtime"), "_tags": ["suid"]}


# ------------------------------------------------------------ auth events
@rule("NIX-AUTH-001", "SSH brute force followed by accepted login", "high", "auth_events",
      technique="T1110", tactic="Credential Access", platform="linux",
      description="Repeated SSH auth failures from a source, then an accepted login, can indicate a successful password-guessing attack.",
      recommendation="Confirm the accepted session's source and user; review what the session did next.")
def nix_ssh_brute(b: Bundle) -> Iterable[Dict]:
    from collections import defaultdict
    fails = defaultdict(int)
    fail_last = {}
    accepted = defaultdict(list)
    for e in b.get("auth_events"):
        g = e.get("groups") or []
        if e.get("kind") == "ssh_failed" and len(g) >= 3:
            src = g[2]
            fails[src] += 1
            fail_last[src] = e.get("timestamp")
        elif e.get("kind") == "ssh_accepted" and len(g) >= 3:
            accepted[g[2]].append((e.get("timestamp"), g[1]))
    for src, n in fails.items():
        if n >= 5:
            yield {"source": src, "failures": n, "later_accepted": bool(accepted.get(src)),
                   "accepted_users": [u for _, u in accepted.get(src, [])][:5],
                   "_severity": "high" if accepted.get(src) else "medium", "_timestamp": fail_last.get(src),
                   "_tags": ["ssh-brute"]}


@rule("NIX-AUTH-002", "User, group, or credential change in auth log", "medium", "auth_events",
      technique="T1136", tactic="Persistence", platform="linux",
      description="The auth log records a user/group being added, a password change, or a failed sudo/su attempt.",
      recommendation="Correlate account changes with the session that made them; unexplained additions are persistence.")
def nix_auth_change(b: Bundle) -> Iterable[Dict]:
    kinds = {"user_added": ("high", "account created"), "group_add": ("medium", "added to group"),
             "group_added": ("medium", "group created"), "password_changed": ("medium", "password changed"),
             "user_deleted": ("medium", "account deleted"), "sudo_failed": ("medium", "failed sudo"),
             "su_failed": ("medium", "failed su")}
    for e in b.get("auth_events"):
        if e.get("kind") in kinds:
            sev, note = kinds[e["kind"]]
            yield {"kind": e.get("kind"), "note": note, "detail": e.get("groups"), "raw": e.get("raw"),
                   "_timestamp": e.get("timestamp"), "_severity": sev, "_tags": ["account-change"]}
