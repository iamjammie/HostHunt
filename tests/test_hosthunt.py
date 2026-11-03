"""End-to-end and unit tests. Run:  python3 -m pytest tests/ -q   (or: python3 tests/test_hosthunt.py)"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hosthunt.models import Bundle, Finding
from hosthunt.util import parse_ts, norm_ts, basename_any
from hosthunt.parse.evtx_xml import parse_wevtutil_xml
from hosthunt.analyse import analyse
from hosthunt.analyse.ioc import IOCSet
from samples.make_samples import build


def _fleet():
    d = tempfile.mkdtemp()
    build(d)
    return [Bundle.load(os.path.join(d, h)) for h in ("WS-01", "WS-02", "WS-03", "WS-BOB")]


def test_timestamp_parsing():
    assert norm_ts("2026-11-03T09:14:22+00:00").startswith("2026-11-03T09:14:22")
    assert norm_ts("20261101091233.123456+000").startswith("2026-11-01T09:12:33")
    assert norm_ts("/Date(1699000000000)/").startswith("2023-")
    assert norm_ts("2026-11-03 09:05:01").startswith("2026-11-03T09:05:01")
    assert norm_ts(1699000000).startswith("2023-")
    assert norm_ts("never") is None and norm_ts("") is None


def test_basename():
    assert basename_any("C:\\Windows\\System32\\svchost.exe") == "svchost.exe"
    assert basename_any("/usr/bin/python3") == "python3"


def test_event_xml_parser():
    xml = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           "<Provider Name='X'/><EventID>7045</EventID><TimeCreated SystemTime='2026-11-03T09:16:05.000Z'/>"
           "<Channel>System</Channel><Computer>H1</Computer></System>"
           "<EventData><Data Name='ServiceName'>Evil</Data></EventData></Event>")
    recs = parse_wevtutil_xml(xml)
    assert len(recs) == 1
    assert recs[0]["event_id"] == 7045
    assert recs[0]["data"]["ServiceName"] == "Evil"


def test_ioc_autoclassify():
    s = IOCSet()
    s.add_auto("185.220.101.47")
    s.add_auto("evil.example.com", "c2")
    s.add_auto("a" * 64)
    s.add_auto("dropper.exe")
    assert "185.220.101.47" in s.ips
    assert "evil.example.com" in s.domains
    assert "a" * 64 in s.hashes
    assert "dropper.exe" in s.filenames
    assert s.label_for("evil.example.com") == "c2"


def test_compromised_host_fires_key_rules():
    bundles = _fleet()
    result = analyse(bundles)
    ids = {f.rule_id for f in result["findings"] if f.host == "WS-BOB"}
    for expected in ("WIN-PROC-001", "WIN-PROC-002", "WIN-PROC-004", "WIN-PROC-005", "WIN-PROC-006",
                     "WIN-SVC-001", "WIN-SVC-002", "WIN-TASK-001", "WIN-RUN-001", "WIN-RUN-002",
                     "WIN-WMI-001", "WIN-DEF-001", "WIN-EVT-001", "WIN-EVT-002", "WIN-EVT-003",
                     "WIN-EVT-004", "WIN-USR-001", "WIN-FILE-001", "NET-001"):
        assert expected in ids, f"expected {expected} to fire on WS-BOB"


def test_clean_hosts_are_quiet():
    bundles = _fleet()
    result = analyse(bundles)
    for host in ("WS-01", "WS-02", "WS-03"):
        high = [f for f in result["findings"] if f.host == host and f.score >= 8]
        assert not high, f"{host} should have no high-severity findings, got {[f.rule_id for f in high]}"


def test_ioc_sweep_matches_everywhere():
    bundles = _fleet()
    s = IOCSet()
    s.add_auto("185.220.101.47", "apt-c2")
    result = analyse(bundles, iocs=s)
    ioc_arts = {f.artefact_type for f in result["findings"] if f.rule_id == "IOC-001"}
    assert {"processes", "network"} <= ioc_arts


def test_stacking_flags_outliers():
    bundles = _fleet()
    result = analyse(bundles)
    stack = [f for f in result["findings"] if f.rule_id == "STACK-001"]
    assert stack, "stacking should flag rare artefacts on WS-BOB"
    assert all("WS-BOB" in f.host for f in stack)


def test_timeline_is_sorted_and_populated():
    result = analyse(_fleet())
    ts = [e.timestamp for e in result["events"]]
    assert ts == sorted(ts)
    assert len(ts) > 10


def test_reports_write(tmp_path=None):
    import tempfile as _t
    from hosthunt.report import write_json, write_markdown, write_html
    result = analyse(_fleet())
    outdir = _t.mkdtemp()
    for fn, ext in ((write_json, "json"), (write_markdown, "md"), (write_html, "html")):
        p = os.path.join(outdir, f"r.{ext}")
        fn(result, p)
        assert os.path.getsize(p) > 500


def test_risk_score_bounds():
    from hosthunt.report.writers import _risk_score
    assert _risk_score([]) == 0
    many = [Finding("X", "t", "critical", "d", "a", {}) for _ in range(50)]
    assert 0 < _risk_score(many) <= 100


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except Exception as exc:  # noqa: BLE001
            print(f"  FAIL {fn.__name__}: {exc!r}")
    print(f"\n{passed}/{len(fns)} passed")
    sys.exit(0 if passed == len(fns) else 1)
