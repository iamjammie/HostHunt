"""Live Linux artefact collector (stdlib only, /proc based, no root required but
collects more with it)."""
from __future__ import annotations

import glob
import os
import pwd
import re
import socket
import stat
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..models import Bundle, now_iso
from ..util import file_times, read_text, run, sha256_file, ts_from_epoch, which

HOME_GLOBS = ["/root", "/home/*"]
AUTORUN_FILES = [
    "/etc/rc.local", "/etc/rc.d/rc.local", "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc",
    "/etc/ld.so.preload", "/etc/environment", "/etc/inittab",
]
AUTORUN_GLOBS = [
    "/etc/profile.d/*", "/etc/init.d/*", "/etc/xdg/autostart/*.desktop", "/etc/update-motd.d/*",
    "/etc/NetworkManager/dispatcher.d/*", "/etc/apt/apt.conf.d/*", "/etc/cron.d/*",
    "/etc/udev/rules.d/*", "/etc/pam.d/*", "/etc/ld.so.conf.d/*",
]
USER_AUTORUN_FILES = [".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile",
                      ".zlogin", ".config/autostart", ".xinitrc", ".xsession", ".config/systemd/user"]
HISTORY_FILES = [".bash_history", ".zsh_history", ".sh_history", ".python_history", ".mysql_history",
                 ".psql_history", ".lesshst", ".viminfo", ".local/share/fish/fish_history"]
SYSTEMD_DIRS = ["/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system",
                "/run/systemd/system", "/etc/systemd/user", "/usr/lib/systemd/user"]
SUID_SCAN_DIRS = ["/bin", "/sbin", "/usr", "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home", "/root",
                  "/srv", "/etc", "/var", "/run", "/mnt", "/media"]
TMP_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/run/user", "/run/shm", "/var/run", "/var/spool"]


class LinuxCollector:
    def __init__(self, hash_files: bool = False, event_limit: int = 5000, quick: bool = False):
        self.hash_files = hash_files
        self.event_limit = event_limit
        self.quick = quick
        self.bundle = Bundle(host=socket.gethostname())
        self.users = self._load_users()

    # ------------------------------------------------------------------ main
    def collect(self) -> Bundle:
        steps = [
            ("host", self.collect_host), ("processes", self.collect_processes),
            ("network", self.collect_network), ("services", self.collect_services),
            ("cron", self.collect_cron), ("autoruns", self.collect_autoruns),
            ("ssh", self.collect_ssh), ("users", self.collect_users),
            ("sudoers", self.collect_sudoers), ("shell_history", self.collect_history),
            ("modules", self.collect_modules), ("tmp_execs", self.collect_tmp_execs),
            ("suid", self.collect_suid), ("auth_events", self.collect_auth_events),
            ("logins", self.collect_logins), ("dns", self.collect_dns),
            ("packages", self.collect_recent_packages), ("containers", self.collect_containers),
        ]
        for name, fn in steps:
            t0 = time.time()
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                self.bundle.errors.append(f"{name}: {exc!r}")
            self.bundle.meta.setdefault("timings", {})[name] = round(time.time() - t0, 2)
        return self.bundle

    # ------------------------------------------------------------- helpers
    @staticmethod
    def _load_users() -> Dict[int, str]:
        try:
            return {p.pw_uid: p.pw_name for p in pwd.getpwall()}
        except Exception:  # noqa: BLE001
            return {}

    def _homes(self) -> List[Dict[str, str]]:
        homes: List[Dict[str, str]] = []
        seen = set()
        try:
            for p in pwd.getpwall():
                if p.pw_dir and os.path.isdir(p.pw_dir) and p.pw_dir not in seen and p.pw_dir != "/":
                    seen.add(p.pw_dir)
                    homes.append({"user": p.pw_name, "home": p.pw_dir})
        except Exception:  # noqa: BLE001
            pass
        for g in HOME_GLOBS:
            for d in glob.glob(g):
                if d not in seen and os.path.isdir(d):
                    seen.add(d)
                    homes.append({"user": os.path.basename(d), "home": d})
        return homes

    # ---------------------------------------------------------------- host
    def collect_host(self) -> None:
        osr = {}
        for line in read_text("/etc/os-release").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                osr[k] = v.strip('"')
        uptime = 0.0
        try:
            uptime = float(read_text("/proc/uptime").split()[0])
        except Exception:  # noqa: BLE001
            pass
        self.bundle.meta.update({
            "hostname": socket.gethostname(),
            "platform": "linux",
            "os": osr.get("PRETTY_NAME", ""),
            "kernel": run(["uname", "-r"]).strip(),
            "arch": run(["uname", "-m"]).strip(),
            "collected_at": now_iso(),
            "collector": "hosthunt-linux",
            "boot_time": ts_from_epoch(time.time() - uptime) if uptime else None,
            "timezone": time.strftime("%Z"),
            "fqdn": socket.getfqdn(),
            "interfaces": self._interfaces(),
            "euid": os.geteuid(),
        })

    @staticmethod
    def _interfaces() -> List[Dict[str, str]]:
        out = []
        txt = run(["ip", "-o", "-4", "addr"]) + run(["ip", "-o", "-6", "addr"])
        for line in txt.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                out.append({"iface": parts[1], "addr": parts[3]})
        return out

    # ----------------------------------------------------------- processes
    def collect_processes(self) -> None:
        recs: List[Dict[str, Any]] = []
        btime = 0
        for line in read_text("/proc/stat").splitlines():
            if line.startswith("btime"):
                btime = int(line.split()[1])
        hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid = int(os.path.basename(pid_dir))
            rec: Dict[str, Any] = {"pid": pid}
            try:
                status = read_text(f"{pid_dir}/status")
                for line in status.splitlines():
                    if line.startswith("Name:"):
                        rec["name"] = line.split(":", 1)[1].strip()
                    elif line.startswith("PPid:"):
                        rec["ppid"] = int(line.split(":", 1)[1].strip())
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        rec["uid"] = uid
                        rec["user"] = self.users.get(uid, str(uid))
                try:
                    rec["exe"] = os.readlink(f"{pid_dir}/exe")
                except OSError as exc:
                    rec["exe"] = f"<{exc.strerror}>"
                try:
                    rec["cwd"] = os.readlink(f"{pid_dir}/cwd")
                except OSError:
                    rec["cwd"] = ""
                with open(f"{pid_dir}/cmdline", "rb") as fh:
                    rec["cmdline"] = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
                st = read_text(f"{pid_dir}/stat")
                m = re.match(r"^\d+ \(.*\) (\S) (.*)$", st, re.S)
                if m:
                    fields = m.group(2).split()
                    # starttime is field 22 (1-indexed) overall; fields[] starts at field 4 (ppid)
                    starttime = int(fields[18]) / hz
                    rec["start_time"] = ts_from_epoch(btime + starttime) if btime else None
                    rec["state"] = m.group(1)
                env = b""
                try:
                    with open(f"{pid_dir}/environ", "rb") as fh:
                        env = fh.read(65536)
                except OSError:
                    pass
                interesting = {}
                for kv in env.split(b"\x00"):
                    if kv.startswith((b"LD_PRELOAD=", b"LD_LIBRARY_PATH=", b"HISTFILE=", b"SSH_CLIENT=",
                                      b"SSH_CONNECTION=", b"PROMPT_COMMAND=", b"BASH_ENV=")):
                        k, _, v = kv.partition(b"=")
                        interesting[k.decode()] = v.decode("utf-8", "replace")[:300]
                if interesting:
                    rec["env"] = interesting
                # memfd / deleted binaries, open fds to deleted files
                try:
                    maps = read_text(f"{pid_dir}/maps", 200000)
                    rec["deleted_maps"] = sorted({l.split()[-1] for l in maps.splitlines()
                                                  if "(deleted)" in l and l.count(" ") >= 5})[:10]
                except Exception:  # noqa: BLE001
                    pass
                if self.hash_files and rec.get("exe", "").startswith("/") and os.path.exists(rec["exe"]):
                    rec["sha256"] = sha256_file(rec["exe"])
                recs.append(rec)
            except Exception:  # noqa: BLE001
                continue
        recs.sort(key=lambda r: r["pid"])
        self.bundle.add("processes", recs)

    # ------------------------------------------------------------- network
    def collect_network(self) -> None:
        inode_to_pid: Dict[str, int] = {}
        for fd in glob.glob("/proc/[0-9]*/fd/*"):
            try:
                link = os.readlink(fd)
            except OSError:
                continue
            if link.startswith("socket:["):
                inode_to_pid[link[8:-1]] = int(fd.split("/")[2])
        pid_name = {p["pid"]: (p.get("name"), p.get("exe"), p.get("user")) for p in self.bundle.get("processes")}
        recs: List[Dict[str, Any]] = []
        tcp_states = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2",
                      "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN",
                      "0B": "CLOSING"}

        def hexaddr(h: str, v6: bool) -> str:
            ip, port = h.split(":")
            if v6:
                b = bytes.fromhex(ip)
                # /proc stores IPv6 as 4 little-endian 32-bit words
                words = [b[i:i + 4][::-1] for i in range(0, 16, 4)]
                addr = socket.inet_ntop(socket.AF_INET6, b"".join(words))
            else:
                addr = socket.inet_ntoa(bytes.fromhex(ip)[::-1])
            return f"{addr}:{int(port, 16)}"

        for proto, path in (("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"),
                            ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")):
            lines = read_text(path, 4_000_000).splitlines()[1:]
            for line in lines:
                f = line.split()
                if len(f) < 10:
                    continue
                try:
                    v6 = proto.endswith("6")
                    local, remote = hexaddr(f[1], v6), hexaddr(f[2], v6)
                except Exception:  # noqa: BLE001
                    continue
                state = tcp_states.get(f[3], f[3]) if proto.startswith("tcp") else ("LISTEN" if f[3] == "07" else "")
                pid = inode_to_pid.get(f[9])
                name, exe, user = pid_name.get(pid, (None, None, None))
                la, lp = local.rsplit(":", 1)
                ra, rp = remote.rsplit(":", 1)
                recs.append({"proto": proto, "local_addr": la, "local_port": int(lp), "remote_addr": ra,
                             "remote_port": int(rp), "state": state, "pid": pid, "process": name,
                             "exe": exe, "user": user})
        self.bundle.add("network", recs)

    # ------------------------------------------------------------ services
    def collect_services(self) -> None:
        recs: List[Dict[str, Any]] = []
        enabled = set()
        for d in SYSTEMD_DIRS:
            for w in glob.glob(f"{d}/*.wants/*") + glob.glob(f"{d}/*.requires/*"):
                enabled.add(os.path.basename(w))
        seen = set()
        unit_dirs = list(SYSTEMD_DIRS)
        for h in self._homes():
            unit_dirs.append(os.path.join(h["home"], ".config/systemd/user"))
        for d in unit_dirs:
            for path in glob.glob(f"{d}/*.service") + glob.glob(f"{d}/*.timer") + glob.glob(f"{d}/*.socket"):
                real = os.path.realpath(path)
                if real in seen:
                    continue
                seen.add(real)
                txt = read_text(path, 64 * 1024)
                rec: Dict[str, Any] = {"name": os.path.basename(path), "path": path, "unit_dir": d,
                                       "enabled": os.path.basename(path) in enabled, **file_times(path)}
                for key in ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload", "User",
                            "WorkingDirectory", "Environment", "Description", "OnCalendar", "OnBootSec",
                            "Unit", "WantedBy", "Type"):
                    m = re.findall(rf"^\s*{key}\s*=\s*(.+)$", txt, re.M)
                    if m:
                        rec[key] = m if len(m) > 1 else m[0]
                rec["type"] = "systemd"
                recs.append(rec)
        for path in glob.glob("/etc/init.d/*"):
            if os.path.isfile(path):
                recs.append({"name": os.path.basename(path), "path": path, "type": "sysv", **file_times(path)})
        if which("systemctl") and not self.quick:
            txt = run(["systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain"], 30)
            states = {}
            for line in txt.splitlines():
                parts = line.split(None, 4)
                if len(parts) >= 4:
                    states[parts[0]] = {"load": parts[1], "active": parts[2], "sub": parts[3]}
            for r in recs:
                if r["name"] in states:
                    r.update(states[r["name"]])
        self.bundle.add("services", recs)

    # ---------------------------------------------------------------- cron
    def collect_cron(self) -> None:
        recs: List[Dict[str, Any]] = []

        def add_file(path: str, user: Optional[str] = None, has_user_field: bool = True) -> None:
            if not os.path.isfile(path):
                return
            times = file_times(path)
            for i, line in enumerate(read_text(path).splitlines(), 1):
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" in s.split()[0] and not s.startswith(("@", "*")):
                    continue  # env assignment
                parts = s.split(None, 6 if has_user_field else 5)
                if s.startswith("@"):
                    sched, rest = parts[0], parts[1:]
                    idx = 1
                else:
                    if len(parts) < 6:
                        continue
                    sched, rest = " ".join(parts[:5]), parts[5:]
                    idx = 5
                if has_user_field and rest:
                    u, cmd = rest[0], " ".join(rest[1:])
                else:
                    u, cmd = user or "", " ".join(rest)
                recs.append({"file": path, "line": i, "schedule": sched, "user": u, "command": cmd,
                             "mtime": times.get("mtime"), "source": "crontab"})
            del idx

        add_file("/etc/crontab")
        for p in glob.glob("/etc/cron.d/*"):
            add_file(p)
        for d in ("/var/spool/cron/crontabs", "/var/spool/cron"):
            for p in glob.glob(f"{d}/*"):
                if os.path.isfile(p):
                    add_file(p, user=os.path.basename(p), has_user_field=False)
        for period in ("hourly", "daily", "weekly", "monthly"):
            for p in glob.glob(f"/etc/cron.{period}/*"):
                recs.append({"file": p, "schedule": period, "user": "root", "command": p, "source": "cron.d-period",
                             "snippet": read_text(p, 2048), **file_times(p)})
        for p in glob.glob("/var/spool/at/*") + glob.glob("/var/spool/atjobs/*") + glob.glob("/var/spool/cron/atjobs/*"):
            if os.path.isfile(p):
                recs.append({"file": p, "schedule": "at", "user": "", "command": read_text(p, 4096)[-1500:],
                             "source": "at", **file_times(p)})
        self.bundle.add("cron", recs)

    # ------------------------------------------------------------ autoruns
    def collect_autoruns(self) -> None:
        recs: List[Dict[str, Any]] = []
        paths = [p for p in AUTORUN_FILES if os.path.exists(p)]
        for g in AUTORUN_GLOBS:
            paths.extend(glob.glob(g))
        for h in self._homes():
            for name in USER_AUTORUN_FILES:
                p = os.path.join(h["home"], name)
                if os.path.isdir(p):
                    paths.extend(glob.glob(f"{p}/*"))
                elif os.path.exists(p):
                    paths.append(p)
        for p in sorted(set(paths)):
            if not os.path.isfile(p):
                continue
            txt = read_text(p, 64 * 1024)
            rec = {"path": p, "owner_home": next((h["user"] for h in self._homes() if p.startswith(h["home"] + "/")), ""),
                   "size": len(txt), **file_times(p)}
            # Only ship lines that could execute something, keep the bundle small
            suspicious_lines = [l.strip() for l in txt.splitlines()
                                if re.search(r"(curl|wget|nc |ncat|bash -i|/dev/tcp|base64|python|perl|php|eval|exec |chmod|"
                                             r"nohup|setsid|/tmp/|/dev/shm|\.so$|LD_PRELOAD|PROMPT_COMMAND|alias |export PATH|"
                                             r"crontab|sshd|authorized_keys|\.onion|http)", l, re.I)
                                and not l.strip().startswith("#")]
            rec["lines"] = suspicious_lines[:50]
            if p == "/etc/ld.so.preload":
                rec["content"] = txt.strip()
            recs.append(rec)
        self.bundle.add("autoruns", recs)

    # ----------------------------------------------------------------- ssh
    def collect_ssh(self) -> None:
        recs: List[Dict[str, Any]] = []
        for h in self._homes():
            for name in ("authorized_keys", "authorized_keys2"):
                p = os.path.join(h["home"], ".ssh", name)
                if not os.path.isfile(p):
                    continue
                times = file_times(p)
                for i, line in enumerate(read_text(p).splitlines(), 1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    m = re.search(r"(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-\S+|sk-\S+)\s+(\S+)\s*(.*)$", s)
                    options = s[: m.start()].strip() if m else ""
                    recs.append({"user": h["user"], "file": p, "line": i, "key_type": m.group(1) if m else "?",
                                 "key_fingerprint": (m.group(2)[-24:] if m else ""), "comment": (m.group(3) if m else s)[:200],
                                 "options": options, "mtime": times.get("mtime"), "record": "authorized_key"})
            for extra in ("config", "known_hosts", "rc"):
                p = os.path.join(h["home"], ".ssh", extra)
                if os.path.isfile(p):
                    recs.append({"user": h["user"], "file": p, "record": extra, "size": os.path.getsize(p), **file_times(p),
                                 "snippet": read_text(p, 2048) if extra != "known_hosts" else ""})
        cfg = read_text("/etc/ssh/sshd_config")
        if cfg:
            notable = {}
            for key in ("PermitRootLogin", "PasswordAuthentication", "AuthorizedKeysFile", "AuthorizedKeysCommand",
                        "PermitEmptyPasswords", "Port", "AllowUsers", "UsePAM", "X11Forwarding", "PubkeyAuthentication"):
                m = re.findall(rf"^\s*{key}\s+(.+)$", cfg, re.M | re.I)
                if m:
                    notable[key] = m[-1].strip()
            recs.append({"user": "", "file": "/etc/ssh/sshd_config", "record": "sshd_config", "settings": notable,
                         **file_times("/etc/ssh/sshd_config")})
        for p in glob.glob("/etc/ssh/sshd_config.d/*"):
            recs.append({"user": "", "file": p, "record": "sshd_config", "snippet": read_text(p, 2048), **file_times(p)})
        self.bundle.add("ssh", recs)

    # --------------------------------------------------------------- users
    def collect_users(self) -> None:
        recs: List[Dict[str, Any]] = []
        shadow: Dict[str, Dict[str, Any]] = {}
        for line in read_text("/etc/shadow").splitlines():
            f = line.split(":")
            if len(f) >= 3:
                pw = f[1]
                status = "locked" if pw.startswith(("!", "*")) else ("EMPTY" if pw == "" else "set")
                last_change = None
                try:
                    if f[2]:
                        last_change = ts_from_epoch(int(f[2]) * 86400)
                except ValueError:
                    pass
                shadow[f[0]] = {"password": status, "pw_last_change": last_change, "hash_prefix": pw[:3] if status == "set" else ""}
        groups: Dict[str, List[str]] = {}
        for line in read_text("/etc/group").splitlines():
            f = line.split(":")
            if len(f) >= 4 and f[3]:
                groups[f[0]] = [m for m in f[3].split(",") if m]
        privileged = {"sudo", "wheel", "admin", "root", "docker", "lxd", "adm", "shadow", "disk"}
        for line in read_text("/etc/passwd").splitlines():
            f = line.split(":")
            if len(f) < 7:
                continue
            name, uid, gid, home, shell = f[0], f[2], f[3], f[5], f[6]
            member_of = [g for g, ms in groups.items() if name in ms]
            rec = {"name": name, "uid": int(uid) if uid.isdigit() else uid, "gid": int(gid) if gid.isdigit() else gid,
                   "home": home, "shell": shell, "groups": member_of,
                   "privileged_groups": sorted(set(member_of) & privileged),
                   "passwd_field": f[1], **shadow.get(name, {})}
            if os.path.isdir(home):
                rec["home_mtime"] = file_times(home).get("mtime")
            recs.append(rec)
        self.bundle.add("users", recs)
        self.bundle.add("groups", [{"group": g, "members": m} for g, m in groups.items()])

    def collect_sudoers(self) -> None:
        recs = []
        for p in ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*"):
            txt = read_text(p)
            if not txt and not os.path.exists(p):
                continue
            rules = [l.strip() for l in txt.splitlines() if l.strip() and not l.strip().startswith("#")
                     and not l.strip().startswith("Defaults")]
            recs.append({"file": p, "rules": rules, "readable": bool(txt) or os.path.getsize(p) == 0, **file_times(p)})
        self.bundle.add("sudoers", recs)

    # ------------------------------------------------------------ history
    def collect_history(self) -> None:
        recs: List[Dict[str, Any]] = []
        for h in self._homes():
            for name in HISTORY_FILES:
                p = os.path.join(h["home"], name)
                if not os.path.isfile(p):
                    continue
                times = file_times(p)
                txt = read_text(p, 2 * 1024 * 1024)
                ts: Optional[str] = None
                n = 0
                for i, line in enumerate(txt.splitlines(), 1):
                    if not line.strip():
                        continue
                    if re.match(r"^#\d{9,10}$", line.strip()):  # HISTTIMEFORMAT marker
                        ts = ts_from_epoch(int(line.strip()[1:]))
                        continue
                    m = re.match(r"^: (\d{9,10}):\d+;(.*)$", line)  # zsh extended
                    if m:
                        ts, line = ts_from_epoch(int(m.group(1))), m.group(2)
                    if name == ".viminfo" and not line.startswith(("'", ">")):
                        continue
                    recs.append({"user": h["user"], "file": p, "line": i, "command": line.strip()[:1000], "timestamp": ts,
                                 "file_mtime": times.get("mtime")})
                    n += 1
                    if n >= 20000:
                        break
        self.bundle.add("shell_history", recs)

    # ------------------------------------------------------------- modules
    def collect_modules(self) -> None:
        kver = run(["uname", "-r"]).strip()
        known = set()
        for root, _, files in os.walk(f"/lib/modules/{kver}") if kver and os.path.isdir(f"/lib/modules/{kver}") else []:
            for f in files:
                if f.startswith(tuple()) or ".ko" in f:
                    known.add(f.split(".ko")[0].replace("-", "_"))
        recs = []
        for line in read_text("/proc/modules").splitlines():
            f = line.split()
            if not f:
                continue
            name = f[0]
            recs.append({"name": name, "size": int(f[1]) if f[1].isdigit() else f[1], "used_by": f[3] if len(f) > 3 else "",
                         "in_modules_dir": (name.replace("-", "_") in known) if known else None,
                         "state": f[4] if len(f) > 4 else ""})
        tainted = read_text("/proc/sys/kernel/tainted").strip()
        self.bundle.meta["kernel_tainted"] = tainted
        self.bundle.add("modules", recs)

    # --------------------------------------------------------- tmp execs
    def collect_tmp_execs(self) -> None:
        recs: List[Dict[str, Any]] = []
        count = 0
        for base in TMP_DIRS:
            if not os.path.isdir(base):
                continue
            for root, dirs, files in os.walk(base):
                if root.count("/") > 6:
                    dirs[:] = []
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    is_exec = bool(st.st_mode & 0o111)
                    hidden = f.startswith(".") or "/." in root
                    is_elf = False
                    try:
                        with open(p, "rb") as fh:
                            head = fh.read(4)
                        is_elf = head == b"\x7fELF"
                        is_script = head[:2] == b"#!"
                    except OSError:
                        is_script = False
                    if is_exec or is_elf or is_script or hidden:
                        rec = {"path": p, "executable": is_exec, "elf": is_elf, "script": is_script, "hidden": hidden,
                               "owner": self.users.get(st.st_uid, str(st.st_uid)), **file_times(p)}
                        if self.hash_files or st.st_size < 10 * 1024 * 1024:
                            rec["sha256"] = sha256_file(p)
                        recs.append(rec)
                        count += 1
                    if count > 2000:
                        break
        self.bundle.add("tmp_execs", recs)

    # ---------------------------------------------------------------- suid
    def collect_suid(self) -> None:
        recs: List[Dict[str, Any]] = []
        skip = ("/proc", "/sys", "/dev", "/snap")
        for base in SUID_SCAN_DIRS:
            if not os.path.isdir(base):
                continue
            for root, dirs, files in os.walk(base):
                if root.startswith(skip):
                    dirs[:] = []
                    continue
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        recs.append({"path": p, "suid": bool(st.st_mode & stat.S_ISUID), "sgid": bool(st.st_mode & stat.S_ISGID),
                                     "owner": self.users.get(st.st_uid, str(st.st_uid)), "mode": oct(st.st_mode & 0o7777),
                                     "mtime": ts_from_epoch(st.st_mtime), "ctime": ts_from_epoch(st.st_ctime), "size": st.st_size})
                if self.quick and len(recs) > 500:
                    break
        self.bundle.add("suid", recs)

    # --------------------------------------------------------- auth events
    AUTH_PATTERNS = [
        (re.compile(r"Failed password for (invalid user )?(\S+) from (\S+) port (\d+)"), "ssh_failed"),
        (re.compile(r"Accepted (\w+) for (\S+) from (\S+) port (\d+)"), "ssh_accepted"),
        (re.compile(r"Invalid user (\S+) from (\S+)"), "ssh_invalid_user"),
        (re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.*)$"), "sudo"),
        (re.compile(r"sudo:\s+(\S+) : .*(incorrect password|NOT in sudoers)"), "sudo_failed"),
        (re.compile(r"session opened for user (\S+)(?:\(uid=\d+\))? by (\S*)"), "session_opened"),
        (re.compile(r"new user: name=(\S+?), UID=(\d+)"), "user_added"),
        (re.compile(r"delete user '(\S+)'"), "user_deleted"),
        (re.compile(r"password changed for (\S+)"), "password_changed"),
        (re.compile(r"add '(\S+)' to group '(\S+)'"), "group_add"),
        (re.compile(r"new group: name=(\S+)"), "group_added"),
        (re.compile(r"Received disconnect from (\S+)"), "ssh_disconnect"),
        (re.compile(r"authentication failure.*rhost=(\S*).*user=(\S+)"), "pam_auth_failure"),
        (re.compile(r"CRON\[\d+\]: \((\S+)\) CMD \((.*)\)"), "cron_exec"),
        (re.compile(r"su: \(to (\S+)\) (\S+) on"), "su"),
        (re.compile(r"su\[\d+\]: FAILED SU \(to (\S+)\) (\S+)"), "su_failed"),
    ]

    def collect_auth_events(self) -> None:
        recs: List[Dict[str, Any]] = []
        sources = [p for p in ("/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1", "/var/log/secure.1")
                   if os.path.isfile(p)]
        lines: List[str] = []
        for p in sources:
            lines.extend(read_text(p, 20 * 1024 * 1024).splitlines()[-self.event_limit:])
        if not lines and which("journalctl"):
            txt = run(["journalctl", "--no-pager", "-o", "short-iso", "-n", str(self.event_limit),
                       "_COMM=sshd", "_COMM=sudo", "_COMM=su", "_COMM=useradd", "_COMM=usermod", "_COMM=passwd",
                       "_COMM=cron", "_COMM=CRON", "_COMM=login", "_COMM=groupadd"], 60)
            lines = txt.splitlines()
        year = datetime.now().year
        for line in lines:
            ts = None
            m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:?\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})", line)
            if m:
                ts = m.group(1)
            else:
                m = re.match(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})", line)
                if m:
                    try:
                        dt = datetime.strptime(f"{year} {m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d %H:%M:%S")
                        ts = dt.replace(tzinfo=timezone.utc).isoformat()
                    except ValueError:
                        ts = None
            for rx, kind in self.AUTH_PATTERNS:
                mm = rx.search(line)
                if mm:
                    recs.append({"timestamp": ts, "kind": kind, "groups": list(mm.groups()), "raw": line[:500]})
                    break
        self.bundle.add("auth_events", recs)

    def collect_logins(self) -> None:
        recs = []
        if which("last"):
            txt = run(["last", "-F", "-w", "-n", "200"], 30)
            for line in txt.splitlines():
                if not line.strip() or line.startswith(("wtmp", "btmp")):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                recs.append({"user": parts[0], "tty": parts[1], "from": parts[2] if len(parts) > 2 and not re.match(r"^[A-Z][a-z]{2}$", parts[2]) else "",
                             "raw": line.strip()})
        if which("lastb") and os.geteuid() == 0:
            txt = run(["lastb", "-F", "-w", "-n", "200"], 30)
            for line in txt.splitlines():
                if line.strip() and not line.startswith("btmp"):
                    recs.append({"user": line.split()[0], "failed": True, "raw": line.strip()})
        self.bundle.add("logins", recs)

    # ----------------------------------------------------------------- dns
    def collect_dns(self) -> None:
        hosts = [l for l in read_text("/etc/hosts").splitlines() if l.strip() and not l.strip().startswith("#")]
        resolv = [l for l in read_text("/etc/resolv.conf").splitlines() if l.strip() and not l.strip().startswith("#")]
        self.bundle.add("dns", [{"hosts": hosts, "resolv": resolv, "hosts_mtime": file_times("/etc/hosts").get("mtime")}])

    def collect_recent_packages(self) -> None:
        recs = []
        for p in ("/var/log/dpkg.log", "/var/log/apt/history.log"):
            if os.path.isfile(p):
                for line in read_text(p, 2_000_000).splitlines()[-400:]:
                    if " install " in line or "Commandline:" in line or " installed " in line:
                        recs.append({"source": p, "line": line.strip()[:300]})
        if which("rpm") and not self.quick:
            txt = run(["rpm", "-qa", "--last"], 30)
            recs.extend({"source": "rpm", "line": l.strip()[:300]} for l in txt.splitlines()[:200])
        self.bundle.add("packages", recs)

    def collect_containers(self) -> None:
        recs = []
        if which("docker"):
            txt = run(["docker", "ps", "-a", "--no-trunc", "--format", "{{.ID}}|{{.Image}}|{{.Command}}|{{.Status}}|{{.Names}}|{{.Ports}}"], 20)
            for line in txt.splitlines():
                f = line.split("|")
                if len(f) >= 5:
                    recs.append({"runtime": "docker", "id": f[0][:12], "image": f[1], "command": f[2], "status": f[3],
                                 "name": f[4], "ports": f[5] if len(f) > 5 else ""})
        if os.path.exists("/.dockerenv"):
            self.bundle.meta["inside_container"] = True
        self.bundle.add("containers", recs)
