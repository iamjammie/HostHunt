<div align="center">

# HostHunt

**Hunting threats through host and endpoint artefacts.**

A dependency-free incident-response triage tool that collects host artefacts and turns them into ATT&CK-mapped findings.

`Version 0.1.0` · Runtime: Python 3.8+ · Core dependencies: **none** (standard library only)

[Quick start](#quick-start) · [What it does](#what-it-does) · the on-the-box companion to **[FluxHunt](https://github.com/iamjammie/FluxHunt)** · [the Hunt suite](https://iamjammie.github.io/FluxHunt/suite.html)

</div>

---

<!-- suite-nav:start -->
> **Part of the [iamjammie Hunt suite](https://iamjammie.github.io/FluxHunt/suite.html)** — open-source, offline-first security tooling and knowledge.
>
> 🧠 [Hunt-Sage](https://github.com/iamjammie/hunt-sage) (knowledge) · 🌊 [FluxHunt](https://github.com/iamjammie/FluxHunt) (wire) · 🖥️ **HostHunt** (box) · 📡 [HostVigil](https://github.com/iamjammie/HostVigil) (fleet) · 🔐 [ADHuntX](https://github.com/iamjammie/ADHuntX) (directory) · 🎯 [Sentinel Matrix](https://github.com/iamjammie/Sentinel-Matrix) (detection coverage) · 🧬 [TTP NEXUS](https://github.com/iamjammie/TTP-Nexus) (frameworks) · 🛡️ [ThreatIntFlux](https://github.com/iamjammie/ThreatIntFlux) (threat intel) · 🔦 [Photonwire](https://github.com/iamjammie/PhotonWire) (air gap) · 🛰️ [SPECTRA](https://github.com/iamjammie/SPECTRA---Space-Cyber-Framework) (space)
>
> [Suite hub](https://iamjammie.github.io/FluxHunt/suite.html) · [All projects](https://github.com/iamjammie)
<!-- suite-nav:end -->

HostHunt is the endpoint-side companion to **[FluxHunt](https://github.com/iamjammie/FluxHunt)** —
together they're the **[Hunt suite](https://iamjammie.github.io/FluxHunt/suite.html)**. Where
FluxHunt hunts on the wire (PCAP traffic analysis in the browser), HostHunt hunts on the box.
It collects the artefacts a responder needs in the first hour of an investigation — running
processes, services, scheduled tasks, autostart locations, network connections, accounts, event
logs, persistence mechanisms — and runs them through an ATT&CK-mapped detection engine, an IOC
sweep, cross-host frequency stacking, and a unified timeline, then writes JSON / Markdown / HTML
reports.

The core is **pure Python standard library** — no third-party dependencies — so the collector can
be dropped onto a suspect host from a USB stick or pushed via your EDR's remote shell / PsExec and
will run on a stock Python 3.8+. That makes it usable on locked-down and air-gapped hosts.

> HostHunt is a **defensive triage** tool. It reads and reasons about host state and maps
> observations to MITRE ATT&CK for an analyst to review. It does not execute, weaponise, or explain
> how to carry out any offensive technique.

## What it does

- **Collects host artefacts live** on **Windows** (PowerShell / built-in binaries, no external
  tools) and **Linux** (`/proc` + config files, mostly no root) — into a portable JSON bundle.
- **Detects attacker behaviour.** 43 detection rules across the intrusion kill-chain —
  masquerading, bad process ancestry, LOLBin & PowerShell signatures, service / task / registry /
  WMI persistence, IFEO & Winlogon hijacks, Defender tampering, log clearing, brute force, UID-0
  backdoors, SUID escalation, rogue SSH keys, rootkit LKMs — each mapped to a MITRE ATT&CK
  technique and tactic.
- **Sweeps for IOCs.** Load hashes / IPs / domains / filenames / strings from `.txt`, `.csv` or
  `.json` (flat, MISP-ish, or typed) and match them against every artefact in the bundle; matches
  carry the threat label and the offending record.
- **Stacks across a fleet.** Artefacts present on only one or two hosts (rare services, tasks,
  autoruns, processes, listeners, modules) are surfaced as outliers — least-frequency-of-occurrence
  hunting a single host can't do.
- **Builds a timeline.** Process starts, event-log entries, logons, account changes, file drops
  and every finding's anchor time, normalised to UTC and interleaved into one sortable narrative.
- **Generates IR reports.** A self-contained single-file **HTML** report (risk gauge, severity
  breakdown, filterable/sortable findings with expandable evidence, an ATT&CK matrix by tactic, the
  timeline, per-host summaries), plus **JSON** for a SIEM and **Markdown** for the case file.

## Quick start

```bash
pip install -e .            # installs the `hosthunt` command
# optional: offline binary .evtx parsing
pip install -e ".[evtx]"
```

Or run straight from source with no install: `python3 -m hosthunt --help`

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

Try it immediately against the bundled demo fleet (3 clean hosts + 1 compromised):

```bash
python3 -m hosthunt analyse "samples/fleet/*" --ioc iocs/sample_iocs.txt -o demo -f html
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
processes (with signature + optional hash, parent/child), services + ServiceDLLs, drivers,
scheduled tasks (CSV + task-XML timestamps), registry autostart (Run keys, Winlogon, IFEO, Active
Setup, LSA, per-user HKU hives) + startup folders, **WMI permanent event subscriptions**, TCP/UDP
connections mapped to owning process, local users / privileged-group membership / hidden accounts,
prefetch, **Windows event logs** (Security / System / PowerShell / Sysmon / TaskScheduler /
TerminalServices / Defender / WMI / BITS / WinRM via `wevtutil`), Defender status + exclusions,
named pipes, SMB shares + sessions, recent dropped files, PowerShell console history, DNS cache +
hosts file, firewall rules.

**Linux** (via `/proc` and config files, mostly no root needed):
processes (exe / cwd / cmdline, start time, deleted-image & memfd detection, LD_PRELOAD and
friends), full socket→PID network table parsed from `/proc/net`, systemd units (system + per-user)
/ SysV init, cron / cron.d / at jobs, login & shell init scripts (`.bashrc`, `profile.d`,
autostart, …), SSH `authorized_keys` / `sshd_config`, users / shadow status / sudoers / privileged
groups, shell history (bash / zsh with timestamps), loaded kernel modules vs on-disk set + taint,
SUID/SGID binaries, world-writable temp executables, auth-log events (SSH, sudo, su, account
changes), `last` / `lastb` logins, DNS / hosts, recent package installs, containers.

## Bundle format

A bundle is just a directory of JSON (plus raw `wevtutil` XML, parsed on load):

```
WS-BOB/
  host.json            # metadata: hostname, OS, collection time, errors, counts
  processes.json       # each artefact type is a JSON list of records
  services.json
  events.xml           # raw `wevtutil ... /f:xml` is parsed on load
  ...
```

Because it's plain JSON / CSV / XML you can **ingest third-party output** by dropping it in with the
right name — e.g. KAPE / Autoruns / `AppCompatCacheParser` CSVs, or a `wevtutil` XML dump — and
HostHunt will analyse it alongside its own collection.

## Honest limitations

- **Heuristic detection.** Findings are heuristics demonstrated against synthetic data. Legitimate
  software (management agents, installers, admin scripts, telemetry) can resemble persistence,
  masquerading, or LOLBin abuse. **Validate against known-good baselines before acting.**
- **Host evidence only.** HostHunt observes endpoint state, not the wire. Correlate with network
  evidence (see **[FluxHunt](https://github.com/iamjammie/FluxHunt)**), EDR, and authentication
  records before concluding.
- **Point-in-time collection.** A live collection is a snapshot; a sophisticated rootkit can hide
  from user-space enumeration. Treat a clean bundle as "nothing found", not "nothing present".
- **ATT&CK mapping is best-effort,** for context and triage prioritisation — not attribution.
- **Not included (needs a backend):** continuous monitoring, agent fleet management, live
  threat-intel lookups, and kernel/memory forensics. HostHunt is first-hour triage, not EDR.

## Responsible use

HostHunt is a **defensive** tool for incident responders, SOC analysts, and system administrators.
Run it only on hosts you are authorised to investigate.

## Testing

```bash
python3 samples/make_samples.py samples/fleet    # build a demo fleet (3 clean + 1 compromised host)
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

Released under the **MIT License** — see [`LICENSE`](LICENSE).
