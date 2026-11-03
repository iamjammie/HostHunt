"""HostHunt command-line interface.

Subcommands
-----------
  collect   Collect artefacts from the local host into a bundle directory.
  analyse   Run the rule engine / IOC sweep / stacking over one or more bundles.
  triage    Collect the local host and analyse it in one shot (fast live triage).
  rules     List the detection rules and their ATT&CK mappings.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys
from typing import List

from . import __version__
from .models import Bundle, SEVERITIES


def _p(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_bundles(paths: List[str]) -> List[Bundle]:
    bundles: List[Bundle] = []
    for path in paths:
        for d in sorted(glob.glob(path)) if any(c in path for c in "*?[") else [path]:
            if os.path.isdir(d):
                bundles.append(Bundle.load(d))
            else:
                _p(f"! not a bundle directory: {d}")
    return bundles


def _emit_reports(result, out_prefix: str, formats: List[str]) -> List[str]:
    from .report import write_json, write_markdown, write_html
    written = []
    for fmt in formats:
        path = f"{out_prefix}.{ 'md' if fmt=='markdown' else fmt }"
        {"json": write_json, "markdown": write_markdown, "html": write_html}[fmt](result, path)
        written.append(path)
    return written


def cmd_collect(args) -> int:
    from .collect import collect_live
    _p(f"[*] collecting live artefacts (hash_files={args.hash_files}, quick={args.quick}) …")
    bundle = collect_live(hash_files=args.hash_files, event_limit=args.event_limit, quick=args.quick)
    bundle.save(args.output)
    _p(f"[+] saved bundle for {bundle.host} -> {args.output}")
    for k, v in sorted(bundle.summary().items()):
        _p(f"      {k:16} {v}")
    if bundle.errors:
        _p(f"[!] {len(bundle.errors)} collection error(s) (see host.json)")
    return 0


def _build_analysis(args):
    from .analyse import analyse
    from .analyse.ioc import IOCSet
    bundles = _load_bundles(args.bundles)
    if not bundles:
        _p("! no bundles loaded")
        return None, None
    iocs = None
    if args.ioc:
        iocs = IOCSet.from_files(args.ioc)
        _p(f"[*] loaded {iocs.count} indicators from {len(args.ioc)} file(s)")
    disabled = set(args.disable_rule or [])
    result = analyse(bundles, iocs=iocs, disabled_rules=disabled, min_severity=args.min_severity)
    return result, bundles


def _print_console(result) -> None:
    from .models import SEVERITY_SCORE
    findings = result["findings"]
    _p(f"\n[=] {len(findings)} finding(s)")
    from collections import Counter
    c = Counter(f.severity for f in findings)
    _p("    " + "  ".join(f"{s}:{c.get(s,0)}" for s in reversed(SEVERITIES) if c.get(s)))
    for f in findings[:40]:
        when = f" @ {f.timestamp}" if f.timestamp else ""
        tech = f" [{f.technique}/{f.tactic}]" if f.technique else ""
        _p(f"  {f.severity.upper():8} {f.rule_id:12} {f.host:16.16} {f.title}{tech}{when}")
    if len(findings) > 40:
        _p(f"  … and {len(findings)-40} more (see report)")


def cmd_analyse(args) -> int:
    result, bundles = _build_analysis(args)
    if result is None:
        return 2
    _print_console(result)
    written = _emit_reports(result, args.output, args.format)
    for w in written:
        _p(f"[+] wrote {w}")
    return 0


def cmd_triage(args) -> int:
    from .collect import collect_live
    from .analyse import analyse
    from .analyse.ioc import IOCSet
    _p("[*] live triage: collecting …")
    bundle = collect_live(hash_files=args.hash_files, event_limit=args.event_limit, quick=args.quick)
    if args.save_bundle:
        bundle.save(args.save_bundle)
        _p(f"[+] bundle saved -> {args.save_bundle}")
    iocs = IOCSet.from_files(args.ioc) if args.ioc else None
    if iocs:
        _p(f"[*] loaded {iocs.count} indicators")
    result = analyse([bundle], iocs=iocs, disabled_rules=set(args.disable_rule or []), min_severity=args.min_severity)
    _print_console(result)
    written = _emit_reports(result, args.output, args.format)
    for w in written:
        _p(f"[+] wrote {w}")
    return 0


def cmd_rules(args) -> int:
    from .analyse import RULES
    rows = sorted(RULES, key=lambda r: (r.platform, r.tactic, r.rule_id))
    if args.json:
        import json
        print(json.dumps([{"id": r.rule_id, "title": r.title, "severity": r.severity, "platform": r.platform,
                           "technique": r.technique, "tactic": r.tactic, "artefact": r.artefact} for r in rows], indent=2))
        return 0
    _p(f"HostHunt {__version__} — {len(rows)} rules\n")
    cur = None
    for r in rows:
        if r.platform != cur:
            cur = r.platform
            print(f"\n== {cur.upper()} ==")
        print(f"  {r.rule_id:14} {r.severity:8} {r.technique or '-':10} {r.tactic or '':24.24} {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hosthunt", description="Host/endpoint artefact collection and IR analysis.")
    ap.add_argument("--version", action="version", version=f"hosthunt {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("collect", help="collect artefacts from the local host")
    c.add_argument("-o", "--output", required=True, help="bundle directory to write")
    c.add_argument("--hash-files", action="store_true", help="SHA-256 process images and dropped files (slower)")
    c.add_argument("--event-limit", type=int, default=5000, help="max events per channel/log (default 5000)")
    c.add_argument("--quick", action="store_true", help="skip the slowest collectors (full SUID walk, signatures)")
    c.set_defaults(func=cmd_collect)

    a = sub.add_parser("analyse", help="analyse one or more collected bundles")
    a.add_argument("bundles", nargs="+", help="bundle directories (globs ok)")
    a.add_argument("-o", "--output", default="hosthunt-report", help="output path prefix")
    a.add_argument("-f", "--format", nargs="+", default=["html", "json"], choices=["html", "json", "markdown"])
    a.add_argument("--ioc", nargs="+", help="IOC file(s): .txt/.csv/.json")
    a.add_argument("--min-severity", default="info", choices=list(SEVERITIES))
    a.add_argument("--disable-rule", nargs="+", help="rule IDs to skip")
    a.set_defaults(func=cmd_analyse)

    t = sub.add_parser("triage", help="collect the local host and analyse in one step")
    t.add_argument("-o", "--output", default="hosthunt-triage", help="output path prefix")
    t.add_argument("-f", "--format", nargs="+", default=["html", "json"], choices=["html", "json", "markdown"])
    t.add_argument("--ioc", nargs="+", help="IOC file(s)")
    t.add_argument("--save-bundle", help="also save the raw bundle to this directory")
    t.add_argument("--hash-files", action="store_true")
    t.add_argument("--event-limit", type=int, default=5000)
    t.add_argument("--quick", action="store_true")
    t.add_argument("--min-severity", default="info", choices=list(SEVERITIES))
    t.add_argument("--disable-rule", nargs="+")
    t.set_defaults(func=cmd_triage)

    r = sub.add_parser("rules", help="list detection rules and ATT&CK mappings")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_rules)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _p("\n! interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
