"""Analysis layer: rule engine, IOC sweep, stacking and timeline."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..models import Bundle, Event, Finding
from .engine import RULES, run_rules
from . import rules_windows, rules_linux, rules_common  # noqa: F401 - registers rules
from .ioc import IOCSet, sweep
from .stacking import stack
from .timeline import build_timeline


def analyse(bundles: List[Bundle], iocs: Optional[IOCSet] = None, disabled_rules: Optional[set] = None,
            min_severity: str = "info") -> Dict[str, Any]:
    from ..models import SEVERITY_SCORE
    threshold = SEVERITY_SCORE.get(min_severity, 1)
    findings: List[Finding] = []
    for b in bundles:
        findings.extend(run_rules(b, disabled=disabled_rules))
        if iocs:
            findings.extend(sweep(b, iocs))
    if len(bundles) > 1:
        findings.extend(stack(bundles))
    findings = [f for f in findings if f.score >= threshold]
    # De-duplicate (same rule + host + evidence)
    seen = set()
    uniq: List[Finding] = []
    for f in findings:
        if f.fid in seen:
            continue
        seen.add(f.fid)
        uniq.append(f)
    uniq.sort(key=lambda f: (-f.score, f.host, f.rule_id))
    events: List[Event] = []
    for b in bundles:
        events.extend(build_timeline(b, uniq))
    events.sort(key=lambda e: e.timestamp)
    return {"findings": uniq, "events": events, "bundles": bundles,
            "rules": [{"id": r.rule_id, "title": r.title, "severity": r.severity, "technique": r.technique,
                       "tactic": r.tactic, "platform": r.platform} for r in RULES]}
