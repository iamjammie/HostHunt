"""Tiny decorator-based rule registry.

A rule is a function ``fn(bundle) -> Iterable[dict]``. Each yielded dict is the
*evidence* for one finding; it may carry ``_severity``, ``_timestamp``, ``_title``
or ``_tags`` keys to override the rule defaults for that particular hit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from ..models import Bundle, Finding
from ..util import norm_ts


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    artefact: str
    technique: str
    tactic: str
    description: str
    recommendation: str
    platform: str
    fn: Callable[[Bundle], Iterable[Dict]]


RULES: List[Rule] = []


def rule(rule_id: str, title: str, severity: str, artefact: str, technique: str = "", tactic: str = "",
         description: str = "", recommendation: str = "", platform: str = "any"):
    def deco(fn: Callable[[Bundle], Iterable[Dict]]):
        RULES.append(Rule(rule_id, title, severity, artefact, technique, tactic, description, recommendation, platform, fn))
        return fn
    return deco


def run_rules(bundle: Bundle, disabled: Optional[set] = None) -> List[Finding]:
    out: List[Finding] = []
    plat = bundle.platform or "any"
    for r in RULES:
        if disabled and r.rule_id in disabled:
            continue
        if r.platform not in ("any", plat) and plat != "":
            continue
        try:
            hits = list(r.fn(bundle) or [])
        except Exception as exc:  # noqa: BLE001
            bundle.errors.append(f"rule {r.rule_id} failed: {exc!r}")
            continue
        for ev in hits:
            if not isinstance(ev, dict):
                continue
            sev = ev.pop("_severity", r.severity)
            ts = ev.pop("_timestamp", None)
            title = ev.pop("_title", r.title)
            tags = ev.pop("_tags", [])
            desc = ev.pop("_description", r.description)
            out.append(Finding(rule_id=r.rule_id, title=title, severity=sev, description=desc,
                               artefact_type=r.artefact, evidence=ev, technique=r.technique, tactic=r.tactic,
                               timestamp=norm_ts(ts) or (ts if isinstance(ts, str) else None), host=bundle.host,
                               recommendation=r.recommendation, tags=list(tags)))
    return out
