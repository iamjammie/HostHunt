"""Build a normalised, time-ordered event stream from a bundle + its findings.

The timeline is the responder's primary narrative artefact: it interleaves process
starts, service installs, logons, account changes, file drops and every finding's
anchor time into one sortable sequence.
"""
from __future__ import annotations

from typing import Any, Dict, List

from ..models import Bundle, Event, Finding
from ..util import basename_any, norm_ts


def _ev(ts, source, summary, host, sev="info", **details) -> Event:
    return Event(timestamp=ts, source=source, summary=summary, host=host, severity=sev, details=details)


def build_timeline(bundle: Bundle, findings: List[Finding]) -> List[Event]:
    events: List[Event] = []
    host = bundle.host
    fmap = {f.fid: f for f in findings if f.host == host or host in (f.host or "")}

    # --- findings (so they interleave with raw events) ---
    for f in findings:
        if f.timestamp and (f.host == host or (f.host and host and host in f.host)):
            events.append(_ev(f.timestamp, f"finding:{f.rule_id}", f.title, f.host, f.severity,
                              finding_id=f.fid, technique=f.technique))

    # --- processes ---
    for p in bundle.get("processes"):
        ts = norm_ts(p.get("start_time"))
        if ts:
            events.append(_ev(ts, "process", f"start {basename_any(p.get('name'))} (pid {p.get('pid')})", host,
                              pid=p.get("pid"), ppid=p.get("ppid"), user=p.get("user"),
                              cmdline=(p.get("cmdline") or "")[:200]))

    # --- windows events ---
    EID = {4688: "process created", 4624: "logon", 4625: "logon failed", 4720: "user account created",
           4722: "account enabled", 4724: "password reset", 4728: "member added to global group",
           4732: "member added to local group", 4672: "special privileges assigned", 1102: "security log cleared",
           7045: "service installed", 4697: "service installed", 4698: "scheduled task created",
           4699: "scheduled task deleted", 4702: "scheduled task updated", 1149: "RDP auth succeeded",
           21: "RDP session logon", 4104: "powershell script block", 4648: "explicit-cred logon",
           1116: "defender detection", 1117: "defender action", 5140: "network share accessed",
           104: "event log cleared", 1074: "system shutdown/restart", 4738: "user account changed",
           4756: "member added to universal group", 4776: "credential validation"}
    for e in bundle.get("events"):
        ts = norm_ts(e.get("timestamp"))
        if not ts:
            continue
        eid = e.get("event_id")
        d = e.get("data", {})
        label = EID.get(eid, f"event {eid}")
        extra = ""
        if eid in (4688,):
            extra = basename_any(d.get("NewProcessName")) + " " + (d.get("CommandLine") or "")[:120]
        elif eid in (4624, 4625, 4648):
            extra = f"{d.get('TargetUserName','')} from {d.get('IpAddress','')} type {d.get('LogonType','')}"
        elif eid in (4720, 4726, 4738):
            extra = d.get("TargetUserName", "")
        elif eid in (7045,):
            extra = f"{d.get('ServiceName','')} -> {(d.get('ImagePath') or '')[:120]}"
        elif eid == 1:  # sysmon process create
            label = "process created (sysmon)"
            extra = basename_any(d.get("Image")) + " " + (d.get("CommandLine") or "")[:120]
        elif eid == 3:
            label = "network connect (sysmon)"
            extra = f"{basename_any(d.get('Image'))} -> {d.get('DestinationIp','')}:{d.get('DestinationPort','')}"
        sev = "high" if eid in (1102, 104, 7045, 4720, 4728, 4732, 1116) else "info"
        events.append(_ev(ts, f"winevt:{e.get('channel','')}", f"{label}: {extra}".strip(), host, sev,
                          event_id=eid))

    # --- linux auth events ---
    for e in bundle.get("auth_events"):
        ts = norm_ts(e.get("timestamp"))
        if ts:
            events.append(_ev(ts, "authlog", f"{e.get('kind')}: {' '.join(str(x) for x in (e.get('groups') or []))}"[:200],
                              host, "info", kind=e.get("kind")))

    # --- shell history (timestamped) ---
    for h in bundle.get("shell_history"):
        ts = norm_ts(h.get("timestamp"))
        if ts:
            events.append(_ev(ts, "history", f"{h.get('user','')}: {(h.get('command') or '')[:160]}", host,
                              "info", user=h.get("user")))

    # --- service install events (7045 handled above) & scheduled tasks created ---
    for t in bundle.get("scheduled_tasks"):
        ts = norm_ts(t.get("xml_ctime"))
        if ts:
            events.append(_ev(ts, "task", f"task created: {t.get('name')}", host, "info"))

    # --- file drops / autoruns with mtimes ---
    for art, verb in (("recent_files", "file"), ("tmp_execs", "tmp-file"), ("prefetch", "prefetch")):
        for r in bundle.get(art):
            ts = norm_ts(r.get("mtime"))
            if ts:
                label = r.get("path") or r.get("executable") or r.get("file") or ""
                events.append(_ev(ts, verb, f"{verb}: {label}"[:200], host, "info"))

    return [e for e in events if e.timestamp]
