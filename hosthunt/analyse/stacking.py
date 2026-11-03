"""Cross-host frequency stacking ("least-frequency-of-occurrence" analysis).

Across a fleet of bundles, artefacts that appear on only one or two hosts are far
more interesting than ones present everywhere. This produces outlier findings that
a single-host view cannot.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Tuple

from ..models import Bundle, Finding
from ..util import basename_any, lower

# (artefact, function producing a stable key, function producing display evidence)
def _svc_key(r):
    return ("service", lower(basename_any(r.get("name") or "")), _img(r.get("path")))

def _task_key(r):
    return ("task", lower(r.get("name") or ""))

def _autorun_key(r):
    return ("autorun", lower(r.get("name") or ""), lower((r.get("value") or "")[:120]))

def _proc_key(r):
    return ("process", lower(basename_any(r.get("name") or "")), _img(r.get("exe")))

def _listen_key(r):
    if lower(r.get("state")) == "listen":
        return ("listener", str(r.get("local_port")), lower(basename_any(r.get("process") or "")))
    return None

def _module_key(r):
    return ("module", lower(r.get("name") or ""))

def _img(path):
    import re
    p = lower(path or "")
    m = re.search(r"([a-z]:\\[^\" ]+\.(?:exe|dll|sys)|/[^ ]+)", p)
    return (m.group(1) if m else p)[:160]


_STACK_DEFS = [
    ("services", _svc_key, "Service"),
    ("scheduled_tasks", _task_key, "Scheduled task"),
    ("autoruns", _autorun_key, "Autostart entry"),
    ("processes", _proc_key, "Process"),
    ("network", _listen_key, "Listening port"),
    ("modules", _module_key, "Kernel module"),
]


def stack(bundles: List[Bundle], rare_threshold: int = 2) -> List[Finding]:
    """Flag artefacts that occur on <= rare_threshold hosts out of the fleet."""
    out: List[Finding] = []
    total = len(bundles)
    if total < 3:
        return out  # stacking only meaningful across a few hosts
    for art, keyfn, label in _STACK_DEFS:
        occ: Dict[Tuple, set] = defaultdict(set)
        sample: Dict[Tuple, Dict] = {}
        for b in bundles:
            for rec in b.get(art):
                if not isinstance(rec, dict):
                    continue
                try:
                    key = keyfn(rec)
                except Exception:  # noqa: BLE001
                    key = None
                if not key:
                    continue
                occ[key].add(b.host)
                sample.setdefault(key, {"host": b.host, "rec": rec})
        for key, hosts in occ.items():
            n = len(hosts)
            if n <= rare_threshold and n < total:
                rec = sample[key]["rec"]
                pct = round(100.0 * n / total, 1)
                out.append(Finding(
                    rule_id="STACK-001", title=f"Rare {label.lower()} across fleet",
                    severity="medium" if n == 1 else "low",
                    description=f"{label} '{_keytext(key)}' is present on {n}/{total} hosts ({pct}%). "
                                "Rare artefacts in an otherwise uniform fleet are prime triage candidates.",
                    artefact_type=art,
                    evidence={"key": _keytext(key), "host_count": n, "fleet_size": total, "hosts": sorted(hosts),
                              "percent": pct, "example_host": sample[key]["host"], "example": _trim(rec)},
                    technique="", tactic="", host=", ".join(sorted(hosts)),
                    recommendation="Compare the outlier host(s) against the fleet baseline; investigate why this artefact is unique.",
                    tags=["stacking", "outlier"]))
    return out


def _keytext(key: Tuple) -> str:
    return " | ".join(str(k) for k in key[1:] if k)


def _trim(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {k: (v[:200] if isinstance(v, str) else v) for k, v in list(rec.items())[:10]
            if isinstance(v, (str, int, float, bool)) or v is None}
