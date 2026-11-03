"""Render analysis results to JSON, Markdown and a self-contained HTML report."""
from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from typing import Any, Dict, List

from ..models import TACTICS, SEVERITIES, now_iso, Event, Finding


def _result_dict(result: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Finding] = result["findings"]
    events: List[Event] = result["events"]
    bundles = result["bundles"]
    sev_counts = Counter(f.severity for f in findings)
    tac_counts = Counter(f.tactic for f in findings if f.tactic)
    host_counts = Counter(f.host for f in findings)
    return {
        "tool": "hosthunt",
        "generated_at": now_iso(),
        "hosts": [{"host": b.host, **{k: v for k, v in b.meta.items() if k not in ("timings",)},
                   "artefact_counts": b.summary(), "collection_errors": b.errors} for b in bundles],
        "summary": {
            "finding_count": len(findings),
            "by_severity": {s: sev_counts.get(s, 0) for s in SEVERITIES},
            "by_tactic": dict(tac_counts),
            "by_host": dict(host_counts),
            "event_count": len(events),
            "risk_score": _risk_score(findings),
        },
        "findings": [f.to_dict() for f in findings],
        "timeline": [e.to_dict() for e in events],
        "attack_matrix": attack_matrix(findings),
    }


def _risk_score(findings: List[Finding]) -> int:
    """A single 0-100 host-risk figure: saturating sum of finding scores."""
    import math
    raw = sum(f.score ** 1.5 for f in findings)
    return min(100, round(100 * (1 - math.exp(-raw / 120))))


def write_json(result: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(_result_dict(result), fh, indent=2, default=str)


def attack_matrix(findings: List[Finding]) -> Dict[str, List[Dict[str, Any]]]:
    matrix: Dict[str, Dict[str, Dict]] = {t: {} for t in TACTICS}
    for f in findings:
        if not f.tactic or f.tactic not in matrix:
            continue
        key = f.technique or f.rule_id
        cell = matrix[f.tactic].setdefault(key, {"technique": f.technique, "titles": set(), "count": 0,
                                                  "max_severity": "info"})
        cell["titles"].add(f.title)
        cell["count"] += 1
        if f.score > (Finding(f.rule_id, "", cell["max_severity"], "", "", {}).score):
            cell["max_severity"] = f.severity
    out: Dict[str, List[Dict[str, Any]]] = {}
    for tac in TACTICS:
        cells = []
        for key, c in matrix[tac].items():
            cells.append({"technique": c["technique"] or key, "titles": sorted(c["titles"]),
                          "count": c["count"], "max_severity": c["max_severity"]})
        if cells:
            out[tac] = sorted(cells, key=lambda c: -c["count"])
    return out


# ---------------------------------------------------------------- Markdown
def write_markdown(result: Dict[str, Any], path: str) -> None:
    d = _result_dict(result)
    L: List[str] = []
    L.append(f"# HostHunt report\n")
    L.append(f"Generated {d['generated_at']} · {len(d['hosts'])} host(s) · "
             f"{d['summary']['finding_count']} findings · risk {d['summary']['risk_score']}/100\n")
    # severity line
    sev = d["summary"]["by_severity"]
    L.append("**Severity:** " + " · ".join(f"{s} {sev[s]}" for s in reversed(SEVERITIES) if sev[s]) + "\n")
    # hosts
    L.append("## Hosts\n")
    for h in d["hosts"]:
        L.append(f"- **{h['host']}** — {h.get('os','?')} ({h.get('platform','?')}), "
                 f"collected {h.get('collected_at','?')}; artefacts: "
                 + ", ".join(f"{k}={v}" for k, v in sorted(h["artefact_counts"].items())))
        if h.get("collection_errors"):
            L.append(f"  - collection errors: {len(h['collection_errors'])}")
    L.append("")
    # ATT&CK coverage
    L.append("## ATT&CK coverage\n")
    for tac in TACTICS:
        cells = d["attack_matrix"].get(tac)
        if cells:
            techs = ", ".join(f"{c['technique']} ({c['count']})" for c in cells)
            L.append(f"- **{tac}**: {techs}")
    L.append("")
    # findings grouped by severity
    L.append("## Findings\n")
    for s in reversed(SEVERITIES):
        group = [f for f in d["findings"] if f["severity"] == s]
        if not group:
            continue
        L.append(f"### {s.upper()} ({len(group)})\n")
        for f in group:
            tech = f" · {f['technique']} {f['tactic']}" if f.get("technique") else (f" · {f['tactic']}" if f.get("tactic") else "")
            L.append(f"- **[{f['rule_id']}] {f['title']}** — `{f['host']}`{tech}")
            if f.get("timestamp"):
                L.append(f"  - when: {f['timestamp']}")
            L.append(f"  - {f['description']}")
            ev = {k: v for k, v in f["evidence"].items() if not k.startswith("_")}
            short = json.dumps(ev, default=str)
            if len(short) > 600:
                short = short[:600] + "…"
            L.append(f"  - evidence: `{short}`")
            if f.get("recommendation"):
                L.append(f"  - action: {f['recommendation']}")
        L.append("")
    # timeline (trimmed)
    L.append("## Timeline (most recent 100)\n")
    for e in d["timeline"][-100:]:
        marker = "⚑ " if e["source"].startswith("finding:") else ""
        L.append(f"- `{e['timestamp']}` [{e['host']}] {marker}{e['source']}: {e['summary']}")
    L.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))


# -------------------------------------------------------------------- HTML
SEV_COLORS = {"critical": "#b3123b", "high": "#e4572e", "medium": "#f3a712", "low": "#4c9f70", "info": "#6b7280"}


def write_html(result: Dict[str, Any], path: str) -> None:
    d = _result_dict(result)
    data_json = json.dumps(d, default=str)
    html_doc = _HTML_TEMPLATE.replace("/*DATA*/null", data_json)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HostHunt report</title>
<style>
:root{--bg:#0f1117;--panel:#171a23;--panel2:#1e222e;--ink:#e7e9ee;--mut:#9aa3b2;--line:#2a2f3d;--accent:#6ea8fe;
--crit:#b3123b;--high:#e4572e;--med:#f3a712;--low:#4c9f70;--info:#6b7280;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:20px 28px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#151824,#0f1117)}
h1{margin:0;font-size:20px;letter-spacing:.3px}h1 span{color:var(--accent)}
.sub{color:var(--mut);margin-top:4px;font-size:13px}
.wrap{padding:20px 28px;max-width:1500px;margin:0 auto}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;min-width:120px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.5px}
.risk{background:conic-gradient(var(--accent) calc(var(--p)*1%),#2a2f3d 0);border-radius:50%;width:74px;height:74px;display:flex;align-items:center;justify-content:center}
.risk div{background:var(--panel);width:58px;height:58px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px}
.sevbar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin:6px 0 2px}
.tabs{display:flex;gap:6px;border-bottom:1px solid var(--line);margin-bottom:16px;flex-wrap:wrap}
.tab{padding:8px 14px;cursor:pointer;color:var(--mut);border-bottom:2px solid transparent}
.tab.active{color:var(--ink);border-color:var(--accent)}
.panel{display:none}.panel.active{display:block}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600;position:sticky;top:0;background:var(--panel2);cursor:pointer;user-select:none}
tr:hover{background:#1b1f2b}
.badge{display:inline-block;padding:1px 8px;border-radius:20px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase}
.pill{display:inline-block;padding:1px 7px;border-radius:5px;font-size:11px;background:#262b38;color:var(--mut);margin:1px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#cbd3e1;white-space:pre-wrap;word-break:break-word}
details summary{cursor:pointer;color:var(--accent)}
.matrix{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.mcol{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:8px}
.mcol h4{margin:0 0 8px;font-size:12px;color:var(--mut);text-transform:uppercase;letter-spacing:.4px}
.mcell{background:var(--panel2);border-radius:6px;padding:6px 8px;margin-bottom:6px;font-size:12px;border-left:3px solid var(--info)}
.mcell b{display:block}.filters{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
input,select{background:var(--panel2);border:1px solid var(--line);color:var(--ink);border-radius:6px;padding:6px 9px;font-size:13px}
.tl{position:relative;margin-left:8px;padding-left:18px;border-left:2px solid var(--line)}
.tlit{position:relative;margin:0 0 10px}.tlit::before{content:"";position:absolute;left:-25px;top:4px;width:10px;height:10px;border-radius:50%;background:var(--info);border:2px solid var(--bg)}
.tlit.f::before{background:var(--accent);width:12px;height:12px;left:-26px}
.tlt{color:var(--mut);font-size:12px}.muted{color:var(--mut)}
a{color:var(--accent)}
</style></head><body>
<header><h1>Host<span>Hunt</span> — endpoint IR report</h1><div class="sub" id="sub"></div></header>
<div class="wrap">
<div class="cards" id="cards"></div>
<div class="tabs" id="tabs">
  <div class="tab active" data-p="findings">Findings</div>
  <div class="tab" data-p="matrix">ATT&amp;CK matrix</div>
  <div class="tab" data-p="timeline">Timeline</div>
  <div class="tab" data-p="hosts">Hosts</div>
</div>
<div class="panel active" id="p-findings">
  <div class="filters">
    <input id="q" placeholder="filter findings…" style="min-width:240px">
    <select id="sevf"><option value="">all severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option><option>info</option></select>
    <select id="hostf"></select>
    <span class="muted" id="fcount"></span>
  </div>
  <table id="ftab"><thead><tr><th data-k="severity">sev</th><th data-k="rule_id">rule</th><th data-k="title">title</th><th data-k="host">host</th><th data-k="tactic">tactic</th><th data-k="technique">tech</th><th data-k="timestamp">when</th></tr></thead><tbody></tbody></table>
</div>
<div class="panel" id="p-matrix"><div class="matrix" id="matrix"></div></div>
<div class="panel" id="p-timeline">
  <div class="filters"><input id="tq" placeholder="filter timeline…" style="min-width:240px"><span class="muted">findings marked ⚑</span></div>
  <div class="tl" id="tl"></div>
</div>
<div class="panel" id="p-hosts"><div id="hosts"></div></div>
</div>
<script>
const D = /*DATA*/null;
const SEV={critical:'#b3123b',high:'#e4572e',medium:'#f3a712',low:'#4c9f70',info:'#6b7280'};
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
document.getElementById('sub').textContent=`generated ${D.generated_at} · ${D.hosts.length} host(s) · ${D.summary.finding_count} findings`;
// cards
const s=D.summary; const cards=document.getElementById('cards');
cards.innerHTML=`<div class="card" style="display:flex;gap:12px;align-items:center"><div class="risk" style="--p:${s.risk_score}"><div>${s.risk_score}</div></div><div><div class="l">risk score</div><div class="muted" style="font-size:12px">0–100 aggregate</div></div></div>`;
const order=['critical','high','medium','low','info'];
let bar=order.map(k=>s.by_severity[k]?`<span style="flex:${s.by_severity[k]};background:${SEV[k]}"></span>`:'').join('');
cards.innerHTML+=`<div class="card"><div class="l">findings by severity</div><div class="n">${s.finding_count}</div><div class="sevbar">${bar}</div><div style="font-size:12px" class="muted">${order.filter(k=>s.by_severity[k]).map(k=>`${k} ${s.by_severity[k]}`).join(' · ')}</div></div>`;
cards.innerHTML+=`<div class="card"><div class="l">events</div><div class="n">${s.event_count}</div></div>`;
const topTac=Object.entries(s.by_tactic).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([k,v])=>`${k} (${v})`).join(', ')||'—';
cards.innerHTML+=`<div class="card"><div class="l">top tactics</div><div style="margin-top:8px">${esc(topTac)}</div></div>`;
// host filter
const hostf=document.getElementById('hostf'); hostf.innerHTML='<option value="">all hosts</option>'+[...new Set(D.findings.map(f=>f.host))].map(h=>`<option>${esc(h)}</option>`).join('');
// findings table
let sortK='severity',sortDir=1; const SVAL={critical:5,high:4,medium:3,low:2,info:1};
function renderF(){
  const q=document.getElementById('q').value.toLowerCase(), sv=document.getElementById('sevf').value, hf=hostf.value;
  let rows=D.findings.filter(f=>(!sv||f.severity===sv)&&(!hf||f.host===hf)&&(!q||JSON.stringify(f).toLowerCase().includes(q)));
  rows.sort((a,b)=>{let x=a[sortK],y=b[sortK];if(sortK==='severity'){x=SVAL[x];y=SVAL[y];}return((x>y)-(x<y))*sortDir||SVAL[b.severity]-SVAL[a.severity];});
  document.getElementById('fcount').textContent=`${rows.length} shown`;
  document.querySelector('#ftab tbody').innerHTML=rows.map(f=>{
    const ev=Object.fromEntries(Object.entries(f.evidence).filter(([k])=>!k.startsWith('_')));
    return `<tr><td><span class="badge" style="background:${SEV[f.severity]}">${f.severity}</span></td>
    <td class="mono">${esc(f.rule_id)}</td>
    <td><b>${esc(f.title)}</b><div class="muted" style="font-size:12px">${esc(f.description)}</div>
    <details><summary>evidence</summary><div class="mono">${esc(JSON.stringify(ev,null,1))}</div>
    ${f.recommendation?`<div class="muted" style="margin-top:6px">▸ ${esc(f.recommendation)}</div>`:''}
    ${(f.tags||[]).map(t=>`<span class="pill">${esc(t)}</span>`).join('')}</details></td>
    <td>${esc(f.host)}</td><td>${esc(f.tactic||'')}</td><td class="mono">${esc(f.technique||'')}</td>
    <td class="mono" style="white-space:nowrap">${esc((f.timestamp||'').replace('T',' ').replace('+00:00','Z'))}</td></tr>`;
  }).join('');
}
document.querySelectorAll('#ftab th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;if(k===sortK)sortDir*=-1;else{sortK=k;sortDir=1;}renderF();});
['q','sevf','hostf'].forEach(id=>document.getElementById(id).oninput=renderF);
hostf.onchange=renderF;
// matrix
const mx=document.getElementById('matrix');
const TACS=Object.keys(D.attack_matrix);
mx.innerHTML=(TACS.length?TACS:['(none)']).map(t=>{const cells=D.attack_matrix[t]||[];
  return `<div class="mcol"><h4>${esc(t)}</h4>${cells.map(c=>`<div class="mcell" style="border-left-color:${SEV[c.max_severity]}"><b>${esc(c.technique)}</b><span class="muted">×${c.count}</span><div class="muted" style="font-size:11px">${esc(c.titles.slice(0,3).join('; '))}</div></div>`).join('')||'<span class="muted">—</span>'}</div>`;
}).join('');
// timeline
function renderTL(){const q=document.getElementById('tq').value.toLowerCase();
  const items=D.timeline.filter(e=>!q||JSON.stringify(e).toLowerCase().includes(q));
  document.getElementById('tl').innerHTML=items.map(e=>{const f=e.source.startsWith('finding:');
    return `<div class="tlit ${f?'f':''}"><div class="tlt">${esc(e.timestamp.replace('T',' ').replace('+00:00','Z'))} · [${esc(e.host)}] · ${esc(e.source)}${e.severity&&e.severity!=='info'?` · <span class="badge" style="background:${SEV[e.severity]}">${e.severity}</span>`:''}</div><div>${f?'⚑ ':''}${esc(e.summary)}</div></div>`;
  }).join('')||'<span class="muted">no events</span>';}
document.getElementById('tq').oninput=renderTL;
// hosts
document.getElementById('hosts').innerHTML=D.hosts.map(h=>`<div class="card" style="display:block;margin-bottom:12px;width:100%">
  <div class="n" style="font-size:18px">${esc(h.host)}</div>
  <div class="muted">${esc(h.os||'?')} · ${esc(h.platform||'?')} · collected ${esc(h.collected_at||'?')}${h.elevated!==undefined?` · elevated=${h.elevated}`:''}${h.euid!==undefined?` · euid=${h.euid}`:''}</div>
  <div style="margin-top:8px">${Object.entries(h.artefact_counts).map(([k,v])=>`<span class="pill">${esc(k)}: ${v}</span>`).join('')}</div>
  ${h.collection_errors&&h.collection_errors.length?`<details style="margin-top:8px"><summary>${h.collection_errors.length} collection error(s)</summary><div class="mono">${esc(h.collection_errors.join('\n'))}</div></details>`:''}
</div>`).join('');
// tabs
document.querySelectorAll('.tab').forEach(t=>t.onclick=()=>{document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.panel').forEach(x=>x.classList.remove('active'));t.classList.add('active');document.getElementById('p-'+t.dataset.p).classList.add('active');});
renderF();renderTL();
</script></body></html>"""
