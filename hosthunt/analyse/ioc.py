"""IOC loading and sweeping across all artefacts in a bundle."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set

from ..models import Bundle, Finding
from ..util import flatten_strings, norm_ts

HASH_RE = re.compile(r"\b([a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
# File extensions that make a dotted token a filename, not a domain (e.g. dropper.exe).
# Deliberately excludes TLD-colliding tokens (com, sh, ...) that would swallow real domains.
FILE_EXT_RE = re.compile(r"\.(exe|dll|sys|ps1|bat|cmd|vbs|jse|hta|scr|jar|msi|wsf|lnk|cpl|ocx|docm|xlsm|pptm|elf|ko)$", re.I)


@dataclass
class IOCSet:
    hashes: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    filenames: Set[str] = field(default_factory=set)
    strings: Set[str] = field(default_factory=set)      # arbitrary substrings
    labels: Dict[str, str] = field(default_factory=dict)  # ioc value -> threat label

    def __bool__(self) -> bool:
        return any((self.hashes, self.ips, self.domains, self.filenames, self.strings))

    @property
    def count(self) -> int:
        return len(self.hashes) + len(self.ips) + len(self.domains) + len(self.filenames) + len(self.strings)

    def label_for(self, value: str) -> str:
        return self.labels.get(value.lower(), "")

    # ---- loading --------------------------------------------------------
    @classmethod
    def from_files(cls, paths: List[str]) -> "IOCSet":
        s = cls()
        for p in paths:
            if not os.path.exists(p):
                continue
            ext = os.path.splitext(p)[1].lower()
            with open(p, encoding="utf-8", errors="replace") as fh:
                if ext == ".json":
                    s._load_json(json.load(fh))
                elif ext == ".csv":
                    import csv
                    fh.seek(0)
                    sample = fh.read(2048)
                    fh.seek(0)
                    header = sample.splitlines()[0].lower() if sample else ""
                    known_cols = ("value", "indicator", "ioc", "hash", "sha256", "md5", "ip", "domain", "filename")
                    if any(col in header.split(",") for col in known_cols):
                        for row in csv.DictReader(fh):
                            s._load_csv_row(row)
                    else:
                        # headerless CSV: first cell is the indicator, optional 2nd cell is a label
                        for row in csv.reader(fh):
                            if row:
                                s.add_auto(row[0].strip(), row[1].strip() if len(row) > 1 else "")
                else:
                    for line in fh:
                        line = line.strip()
                        if "," in line and " " not in line.split(",", 1)[0]:
                            val, _, lab = line.partition(",")
                            s.add_auto(val.strip(), lab.strip())
                        else:
                            s.add_auto(line)
        return s

    def _load_json(self, data: Any) -> None:
        # Accept {"hashes": [...], "ips": [...], ...} or a flat list, or MISP-ish [{"value","type","label"}]
        if isinstance(data, dict) and any(k in data for k in ("hashes", "ips", "domains", "filenames", "strings")):
            for k in ("hashes", "ips", "domains", "filenames", "strings"):
                for v in data.get(k, []):
                    getattr(self, k).add(str(v).lower().strip())
            for v, lab in (data.get("labels") or {}).items():
                self.labels[str(v).lower()] = lab
            return
        items = data if isinstance(data, list) else data.get("indicators", []) if isinstance(data, dict) else []
        for it in items:
            if isinstance(it, str):
                self.add_auto(it)
            elif isinstance(it, dict):
                val = str(it.get("value") or it.get("indicator") or it.get("ioc") or "").strip()
                label = it.get("label") or it.get("threat") or it.get("comment") or it.get("type") or ""
                self.add_auto(val, label)

    def _load_csv_row(self, row: Dict[str, str]) -> None:
        val = ""
        for key in ("value", "indicator", "ioc", "hash", "sha256", "md5", "ip", "domain", "filename"):
            if row.get(key):
                val = row[key].strip()
                break
        label = row.get("label") or row.get("threat") or row.get("description") or row.get("type") or ""
        if val:
            self.add_auto(val, label)

    def add_auto(self, value: str, label: str = "") -> None:
        if not value or value.startswith("#"):
            return
        v = value.strip().strip('"')
        low = v.lower()
        has_path_sep = "/" in v or "\\" in v
        base = re.split(r"[\\/]", v)[-1]
        if HASH_RE.fullmatch(v):
            self.hashes.add(low)
        elif self._is_ip(v):
            self.ips.add(low)
        elif has_path_sep or FILE_EXT_RE.search(base):
            # A path, or a bare name with a file extension, is a filename IOC.
            self.filenames.add(base.lower().strip('"'))
        elif DOMAIN_RE.fullmatch(v) and "." in v and not v.replace(".", "").isdigit():
            self.domains.add(low)
        else:
            self.strings.add(low)
        if label:
            self.labels[low] = label

    @staticmethod
    def _is_ip(v: str) -> bool:
        try:
            ipaddress.ip_address(v)
            return True
        except ValueError:
            return False


# Which artefact fields to pull candidate values from, per matching dimension.
_SWEEP_ARTEFACTS = ["processes", "network", "services", "scheduled_tasks", "autoruns", "cron", "shell_history",
                    "wmi_subscriptions", "ssh", "dns", "recent_files", "tmp_execs", "modules", "drivers",
                    "events", "auth_events", "firewall"]


def sweep(bundle: Bundle, iocs: IOCSet) -> List[Finding]:
    out: List[Finding] = []
    for art in _SWEEP_ARTEFACTS:
        for rec in bundle.get(art):
            if not isinstance(rec, dict):
                continue
            matched = _match_record(rec, iocs)
            if not matched:
                continue
            # Build one finding per record, listing every indicator it hit.
            kinds = sorted({m[0] for m in matched})
            values = [m[1] for m in matched]
            labels = sorted({iocs.label_for(m[1]) for m in matched if iocs.label_for(m[1])})
            sev = "critical" if any(k == "hash" for k, _ in matched) else "high"
            ts = rec.get("start_time") or rec.get("timestamp") or rec.get("mtime") or rec.get("last_run")
            ev = {"artefact": art, "matched_kinds": kinds, "matched_values": values,
                  "threat_labels": labels, "record": _trim_record(rec)}
            out.append(Finding(
                rule_id="IOC-001", title=f"IOC match in {art}", severity=sev,
                description="An artefact contains a value present in the supplied indicator set: " + ", ".join(values[:6]),
                artefact_type=art, evidence=ev, technique="", tactic="",
                timestamp=norm_ts(ts), host=bundle.host,
                recommendation="Treat the host as in-scope for this indicator; pivot to every artefact and other hosts that reference it.",
                tags=["ioc-match"] + kinds + (["labelled"] if labels else [])))
    return out


def _match_record(rec: Dict[str, Any], iocs: IOCSet) -> List[tuple]:
    matched: List[tuple] = []
    # Direct hash fields first (exact).
    for hk in ("sha256", "md5", "sha1", "hash"):
        hv = str(rec.get(hk) or "").lower()
        if hv and hv in iocs.hashes:
            matched.append(("hash", hv))
    text_values = list(flatten_strings(rec))
    blob = "\n".join(text_values).lower()
    for h in iocs.hashes:
        if h in blob:
            matched.append(("hash", h))
    if iocs.ips:
        for ip in set(IPV4_RE.findall(blob)):
            if ip in iocs.ips:
                matched.append(("ip", ip))
    if iocs.domains:
        for tv in text_values:
            low = tv.lower()
            for d in iocs.domains:
                if d == low or low.endswith("." + d) or ("//" + d in low) or ("/" + d + "/" in low) or (d + "/" in low) or (d + ":" in low):
                    matched.append(("domain", d))
    if iocs.filenames:
        for tv in text_values:
            base = re.split(r"[\\/]", tv.strip().strip('"'))[-1].lower()
            if base in iocs.filenames:
                matched.append(("filename", base))
    if iocs.strings:
        for s in iocs.strings:
            if s and s in blob:
                matched.append(("string", s))
    # De-duplicate (kind,value)
    return sorted(set(matched))


def _trim_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in rec.items():
        if isinstance(v, str) and len(v) > 400:
            out[k] = v[:400] + "…"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
        elif isinstance(v, dict):
            out[k] = {kk: (str(vv)[:200]) for kk, vv in list(v.items())[:12]}
        elif isinstance(v, list):
            out[k] = v[:12]
    return out


def extract_observables(bundle: Bundle) -> Dict[str, List[str]]:
    """Harvest candidate IOCs from a bundle (for building a watchlist / sharing)."""
    ips, domains, hashes = set(), set(), set()
    for art in ("network", "processes", "shell_history", "autoruns", "cron", "services", "dns", "scheduled_tasks"):
        for rec in bundle.get(art):
            blob = "\n".join(flatten_strings(rec))
            for ip in IPV4_RE.findall(blob):
                try:
                    o = ipaddress.ip_address(ip)
                    if not (o.is_private or o.is_loopback or o.is_multicast or o.is_reserved or o.is_unspecified):
                        ips.add(ip)
                except ValueError:
                    pass
            for h in HASH_RE.findall(blob):
                hashes.add(h.lower())
    return {"ips": sorted(ips), "domains": sorted(domains), "hashes": sorted(hashes)}
