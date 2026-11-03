"""Parse Windows event XML (as emitted by ``wevtutil qe ... /f:xml``) into records.

Normalised event record::

    {"timestamp": "2026-11-01T09:12:33+00:00", "event_id": 4688, "channel": "Security",
     "provider": "Microsoft-Windows-Security-Auditing", "computer": "WS01",
     "data": {"NewProcessName": "...", "CommandLine": "..."}, "host": "WS01"}

Also exposes :func:`parse_evtx_file` which uses the optional ``python-evtx`` package
to read ``.evtx`` files offline.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, Iterable, List

NS_RE = re.compile(r"\{[^}]+\}")


def _strip_ns(tag: str) -> str:
    return NS_RE.sub("", tag)


def _event_to_record(ev: ET.Element, host: str = "") -> Dict[str, Any]:
    rec: Dict[str, Any] = {"timestamp": None, "event_id": None, "channel": "", "provider": "",
                           "computer": "", "data": {}, "host": host}
    for child in ev:
        tag = _strip_ns(child.tag)
        if tag == "System":
            for s in child:
                st = _strip_ns(s.tag)
                if st == "Provider":
                    rec["provider"] = s.attrib.get("Name", "")
                elif st == "EventID":
                    try:
                        rec["event_id"] = int((s.text or "0").strip())
                    except ValueError:
                        rec["event_id"] = s.text
                elif st == "TimeCreated":
                    rec["timestamp"] = s.attrib.get("SystemTime")
                elif st == "Channel":
                    rec["channel"] = s.text or ""
                elif st == "Computer":
                    rec["computer"] = s.text or ""
                elif st == "EventRecordID":
                    rec["record_id"] = s.text
        elif tag == "EventData":
            i = 0
            for d in child:
                name = d.attrib.get("Name") or f"Data{i}"
                rec["data"][name] = (d.text or "").strip()
                i += 1
        elif tag == "UserData":
            # Vendor-specific payloads (TaskScheduler, TerminalServices, Sysmon older formats)
            for grp in child.iter():
                t = _strip_ns(grp.tag)
                if grp.text and grp.text.strip() and len(list(grp)) == 0:
                    rec["data"][t] = grp.text.strip()
        elif tag == "RenderingInfo":
            for r in child:
                if _strip_ns(r.tag) == "Message" and r.text:
                    rec["message"] = r.text.strip()[:2000]
    if not rec["host"]:
        rec["host"] = rec["computer"]
    return rec


def parse_wevtutil_xml(text: str, host: str = "") -> List[Dict[str, Any]]:
    """wevtutil emits a sequence of ``<Event>`` elements with no root; wrap and parse."""
    text = text.strip()
    if not text:
        return []
    if not text.startswith("<Events"):
        text = "<Events>" + text + "</Events>"
    records: List[Dict[str, Any]] = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Fall back to per-event parsing so one bad event doesn't lose the lot
        for m in re.finditer(r"<Event[ >].*?</Event>", text, re.S):
            try:
                records.append(_event_to_record(ET.fromstring(m.group(0)), host))
            except ET.ParseError:
                continue
        return records
    for ev in root:
        if _strip_ns(ev.tag) == "Event":
            records.append(_event_to_record(ev, host))
    return records


def parse_evtx_file(path: str, host: str = "") -> List[Dict[str, Any]]:
    """Parse a binary .evtx file. Requires ``pip install python-evtx``."""
    try:
        import Evtx.Evtx as evtx  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("python-evtx is required for .evtx parsing: pip install python-evtx") from exc
    out: List[Dict[str, Any]] = []
    with evtx.Evtx(path) as log:
        for rec in log.records():
            try:
                out.append(_event_to_record(ET.fromstring(rec.xml()), host))
            except Exception:  # noqa: BLE001
                continue
    return out


def iter_records_from_xml_files(paths: Iterable[str], host: str = "") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            out.extend(parse_wevtutil_xml(fh.read(), host))
    return out
