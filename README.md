# HostHunt

**Host/endpoint artefact collection and analysis for incident response.**

HostHunt is the on-the-box companion to **FluxHunt**: where FluxHunt hunts on the
wire, HostHunt hunts on the endpoint. It collects the artefacts a responder needs
in the first hour of an investigation — running processes, services, scheduled
tasks, autostart locations, network connections, accounts, event logs, persistence
mechanisms — and runs them through an ATT&CK-mapped detection engine, an IOC sweep,
cross-host frequency stacking, and a unified timeline, then writes JSON / Markdown /
HTML reports.

It is **pure Python standard library** (no third-party dependencies for the core),
so the collector can be dropped onto a suspect host from a USB stick or pushed via
your EDR's remote-shell / PsExec and will run on a stock Python 3.8+.

> HostHunt is a **defensive triage** tool. It reads and reasons about host state and
> maps observations to MITRE ATT&CK for an analyst to review. It does not execute,
> weaponise, or explain how to carry out any offensive technique.

---

## Install

```bash
pip install -e .            # installs the `hosthunt` command
# optional: offline binary .evtx parsing
pip install -e ".[evtx]"
```

Or run straight from source with no install:

```bash
python3 -m hosthunt --help
```

## Quick start

```bash
# 1. Live triage on the box you're sitting at (collect + analyse + report in one go)
hosthunt triage -o case42 --ioc iocs/sample_iocs.txt
#    -> case42.html, case42.json

# 2. Collect now, analyse later / elsewhere (preserves the raw bundle for the case file)
hosthunt collect -o bundles/WS-BOB --hash-files
hosthunt analyse bundles/WS-BOB --ioc threatintel.csv -o WS-BOB-report -f html json markdown

# 3. Fleet sweep — point it at many bundles and let stacking surface the outliers
hosthunt analyse "bundles/*" -o fleet -f html

# 4. See every rule and its ATT&CK mapping
hosthunt rules
```

## Subcommands

| Command | What it does |
|---|---|
| `collect` | Collect artefacts from the local host into a **bundle** directory. Windows and Linux. |
| `analyse` | Run the detection engine, IOC sweep and stacking over one or more bundles; write reports. |
| `triage`  | `collect` the local host and `analyse` it in one step — fastest path to a verdict. |
| `rules`   | List the detection rules and their ATT&CK technique/tactic mappings (`--json` for machine form). |

Useful flags: `--ioc FILE...`, `--min-severity {info,low,medium,high,critical}`,
`--disable-rule ID...`, `--hash-files`, `--quick`, `-f/--format html json markdown`.

## What it collects

**Windows** (via PowerShell / built-in binaries, no external tools):
processes (with signature + optional hash, parent/child), services + ServiceDLLs,
drivers, scheduled tasks (CSV + task-XML timestamps), registry autostart (Run keys,
Winlogon, IFEO, Active Setup, LSA, per-user HKU hives) + startup folders, **WMI
permanent event subscriptions**, TCP/UDP connections mapped to owning process,
local users / privileged-group membership / hidden accounts, prefetch, **Windows
event logs** (Security/System/PowerShell/Sysmon/TaskScheduler/TerminalServices/
Defender/WMI/BITS/WinRM via `wevtutil`), Defender status + exclusions, named pipes,
SMB shares + sessions, recent dropped files, PowerShell console history, DNS cache
+ hosts file, firewall rules.

**Linux** (via `/proc` and config files, mostly no root needed):
processes (exe/cwd/cmdline, start time, deleted-image & memfd detection, LD_PRELOAD
and friends), full socket→PID network table parsed from `/proc/net`, systemd units
(system + per-user) / SysV init, cron / cron.d / at jobs, login & shell init scripts
(`.bashrc`, `profile.d`, autostart, …), SSH `authorized_keys` / `sshd_config`,
users / shadow status / sudoers / privileged groups, shell history (bash/zsh with
timestamps), loaded kernel modules vs on-disk set + taint, SUID/SGID binaries,
world-writable temp executables, auth-log events (SSH, sudo, su, account changes),
`last`/`lastb` logins, DNS/hosts, recent package installs, containers.

## Analysis

- **Detection rules** — 43 rules, each mapped to a MITRE ATT&CK technique + tactic.
  Covers masquerading, bad process ancestry, LOLBin & PowerShell signatures, service /
  task / registry / WMI persistence, IFEO & Winlogon hijacks, Defender tampering, log
  clearing, brute-force patterns, UID-0 backdoors, SUID escalation, rogue SSH keys,
  rootkit LKMs, and more. Rules are a small decorator registry — add one in a few lines.
- **IOC sweep** — load hashes / IPs / domains / filenames / strings from `.txt`, `.csv`
  (headered or not) or `.json` (flat, MISP-ish, or typed). Every artefact in the bundle
  is swept; matches become `IOC-001` findings carrying the threat label and the record.
- **Cross-host stacking** — across a fleet, artefacts present on only one or two hosts
  (rare services, tasks, autoruns, processes, listeners, modules) are surfaced as
  outliers — least-frequency-of-occurrence hunting a single host can't do.
- **Timeline** — process starts, event-log entries, logons, account changes, file
  drops and every finding's anchor time, normalised to UTC and interleaved into one
  sortable narrative.
- **Risk score** — a single saturating 0–100 figure per report.

## Reports

- **HTML** — a self-contained single file (no network, no dependencies): risk gauge,
  severity breakdown, filterable/sortable findings with expandable evidence, an
  ATT&CK matrix laid out by tactic, the timeline, and per-host summaries.
- **JSON** — the full structured result for piping into a SIEM / case management.
- **Markdown** — a readable report for the ticket or the case file.

## Bundle format

A bundle is just a directory:

```
WS-BOB/
  host.json            # metadata: hostname, OS, collection time, errors, counts
  processes.json       # each artefact type is a JSON list of records
  services.json
  events.xml           # raw `wevtutil ... /f:xml` is parsed on load
  ...
```

Because it's plain JSON/CSV/XML you can **ingest third-party output** by dropping it
in with the right name — e.g. KAPE / Autoruns / `AppCompatCacheParser` CSVs, or a
`wevtutil` XML dump — and HostHunt will analyse it alongside its own collection.

## Testing / demo

```bash
python3 samples/make_samples.py samples/fleet    # build a demo fleet (3 clean + 1 compromised host)
python3 -m hosthunt analyse "samples/fleet/*" --ioc iocs/sample_iocs.txt -o demo -f html
python3 tests/test_hosthunt.py                   # or: python3 -m pytest tests/ -q
```

## Layout

```
hosthunt/
  collect/   windows.py · linux.py      live collectors
  parse/     evtx_xml.py                 wevtutil/.evtx → records
  analyse/   engine.py rules_*.py patterns.py ioc.py stacking.py timeline.py
  report/    writers.py                  JSON / Markdown / self-contained HTML
  cli.py models.py util.py
```

## License

MIT.
