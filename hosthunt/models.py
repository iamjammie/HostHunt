"""Core data models shared by collectors, analysers and reporters."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_SCORE = {"info": 1, "low": 3, "medium": 6, "high": 8, "critical": 10}

# MITRE ATT&CK Enterprise tactics in kill-chain order (used for the report matrix)
TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    artefact_type: str
    evidence: Dict[str, Any]
    technique: str = ""
    tactic: str = ""
    timestamp: Optional[str] = None
    host: str = ""
    recommendation: str = ""
    tags: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return SEVERITY_SCORE.get(self.severity, 1)

    @property
    def fid(self) -> str:
        raw = json.dumps([self.rule_id, self.host, self.evidence], sort_keys=True, default=str)
        return hashlib.sha1(raw.encode()).hexdigest()[:10]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.fid
        d["score"] = self.score
        return d


@dataclass
class Event:
    """A normalised, time-stamped observation used to build the timeline."""
    timestamp: str
    source: str
    summary: str
    host: str = ""
    severity: str = "info"
    details: Dict[str, Any] = field(default_factory=dict)
    finding_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Bundle:
    """A collected set of artefacts from one host.

    On disk a bundle is a directory of ``<artefact_type>.json`` files (each a JSON
    list of records) plus ``host.json`` holding metadata. CSV files are accepted too
    (handy for ingesting output from KAPE, Autoruns, AppCompatCacheParser etc.).
    """

    def __init__(self, host: str = "", meta: Optional[Dict[str, Any]] = None):
        self.host = host
        self.meta: Dict[str, Any] = meta or {}
        self.artefacts: Dict[str, List[Dict[str, Any]]] = {}
        self.errors: List[str] = []

    # -- access -------------------------------------------------------------
    def get(self, artefact_type: str) -> List[Dict[str, Any]]:
        return self.artefacts.get(artefact_type, [])

    def add(self, artefact_type: str, records: List[Dict[str, Any]]) -> None:
        self.artefacts.setdefault(artefact_type, []).extend(records)

    @property
    def platform(self) -> str:
        return (self.meta.get("platform") or "").lower()

    def summary(self) -> Dict[str, int]:
        return {k: len(v) for k, v in sorted(self.artefacts.items())}

    # -- persistence --------------------------------------------------------
    def save(self, directory: str) -> None:
        import os
        os.makedirs(directory, exist_ok=True)
        meta = dict(self.meta)
        meta.setdefault("hostname", self.host)
        meta["artefact_counts"] = self.summary()
        meta["errors"] = self.errors
        with open(os.path.join(directory, "host.json"), "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=1, default=str)
        for name, records in self.artefacts.items():
            with open(os.path.join(directory, f"{name}.json"), "w", encoding="utf-8") as fh:
                json.dump(records, fh, indent=1, default=str)

    @classmethod
    def load(cls, directory: str) -> "Bundle":
        import csv
        import os
        from .parse import evtx_xml

        meta: Dict[str, Any] = {}
        meta_path = os.path.join(directory, "host.json")
        if os.path.exists(meta_path):
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
        host = meta.get("hostname") or os.path.basename(os.path.abspath(directory))
        b = cls(host=host, meta=meta)
        for fn in sorted(os.listdir(directory)):
            path = os.path.join(directory, fn)
            stem, ext = os.path.splitext(fn)
            ext = ext.lower()
            try:
                if fn == "host.json":
                    continue
                if ext == ".json":
                    with open(path, encoding="utf-8") as fh:
                        data = json.load(fh)
                    if isinstance(data, dict):
                        data = [data]
                    b.add(stem, data)
                elif ext == ".csv":
                    with open(path, encoding="utf-8-sig", newline="") as fh:
                        b.add(stem, list(csv.DictReader(fh)))
                elif ext == ".xml" and stem.startswith("events"):
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        b.add("events", evtx_xml.parse_wevtutil_xml(fh.read(), host=host))
                elif ext == ".jsonl":
                    with open(path, encoding="utf-8") as fh:
                        b.add(stem, [json.loads(l) for l in fh if l.strip()])
            except Exception as exc:  # noqa: BLE001 - keep loading the rest
                b.errors.append(f"{fn}: {exc}")
        return b
