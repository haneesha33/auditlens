"""Build a self-contained readiness dashboard (one HTML file) from AuditLens evidence records.

Usage:
    python -m auditlens.dashboard --evidence-dir ./evidence --prs prs.json --repo owner/name --out site/index.html

- Reads every evidence-*.json under --evidence-dir (recursively); keeps the latest record per PR.
- --prs (optional) is `gh pr list --json number,title,state,url` output; closed/merged PRs are
  shown but don't count toward open findings or readiness.
- "Readiness" here is change-review readiness: the share of in-scope controls with no open
  findings across open PRs. It is not an audit opinion, and the page says so.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import risk_key

FRAMEWORK_ORDER = ["SOC 2", "ISO 27001", "ISO 42001", "NIST AI RMF", "OWASP LLM"]
SEV = ["critical", "high", "medium", "low"]


def load_evidence(evidence_dir: Path) -> list[dict]:
    latest: dict[str, dict] = {}
    for path in sorted(evidence_dir.rglob("evidence-*.json")):
        try:
            rec = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        key = str(rec.get("pr") or rec.get("head_sha"))
        if key not in latest or rec.get("generated_at", "") > latest[key].get("generated_at", ""):
            latest[key] = rec
    return sorted(latest.values(), key=lambda r: (r.get("pr") or 0))


def _norm_status(s: str) -> str:
    return {"pass": "no_findings"}.get(s, s)  # evidence v1 used "pass" for "no findings"


def summarize(records: list[dict], prs: dict[int, dict], repo: str) -> dict:
    pr_rows, open_records = [], []
    for rec in records:
        num = rec.get("pr")
        meta = prs.get(num, {})
        state = (meta.get("state") or "OPEN").upper()
        sev_counts = {s: sum(1 for f in rec.get("findings", []) if f.get("severity") == s) for s in SEV}
        kev = sum(1 for d in rec.get("dependencies", []) if d.get("kev"))
        verdict = "Blocking" if sev_counts["critical"] else ("Needs attention" if sev_counts["high"] else "Pass")
        pr_rows.append({
            "number": num, "title": meta.get("title") or f"PR #{num}",
            "url": meta.get("url") or (f"https://github.com/{repo}/pull/{num}" if repo and num else ""),
            "state": state, "verdict": verdict, "severity": sev_counts, "kev": kev,
            "ai": bool(rec.get("ai_inventory")), "sha": (rec.get("head_sha") or "")[:7],
            "reviewed_at": rec.get("generated_at", ""), "files": rec.get("changed_files", []),
        })
        if state == "OPEN":
            open_records.append(rec)

    # Control catalog (titles + framework refs) from the newest record that has it.
    catalog: dict[str, dict] = {}
    for rec in records:
        for c in rec.get("controls", []):
            catalog.setdefault(c["id"], {"id": c["id"], "title": c.get("title", ""), "frameworks": c.get("frameworks", {})})

    # Matrix: control x PR status. Aggregate status across OPEN PRs only.
    matrix = {}
    for rec in records:
        for c in rec.get("controls", []):
            matrix.setdefault(c["id"], {})[str(rec.get("pr"))] = {
                "status": _norm_status(c.get("status", "")), "count": c.get("finding_count", 0)}
    agg = {}
    for cid in catalog:
        statuses = [_norm_status(c.get("status", "")) for rec in open_records for c in rec.get("controls", []) if c["id"] == cid]
        if "fail" in statuses:
            agg[cid] = "fail"
        elif any(s in ("no_findings", "performed") for s in statuses):
            agg[cid] = "clear"
        else:
            agg[cid] = "not_applicable"

    frameworks = []
    for fw in FRAMEWORK_ORDER:
        ids = [cid for cid, c in catalog.items() if fw in c["frameworks"]]
        in_scope = [cid for cid in ids if agg[cid] != "not_applicable"]
        failing = [cid for cid in in_scope if agg[cid] == "fail"]
        refs = sorted({r for cid in failing for r in catalog[cid]["frameworks"].get(fw, [])})
        frameworks.append({
            "name": fw, "total": len(ids), "in_scope": len(in_scope), "failing": len(failing),
            "clear": len(in_scope) - len(failing),
            "pct": round(100 * (len(in_scope) - len(failing)) / len(in_scope)) if in_scope else None,
            "failing_refs": refs,
        })

    findings = []
    for rec in open_records:
        for f in rec.get("findings", []):
            if f.get("severity") in ("critical", "high"):
                findings.append({**f, "pr": rec.get("pr")})
    findings.sort(key=lambda f: (*risk_key(f["severity"], f.get("detail", "")), f.get("pr") or 0))

    ai_systems = []
    for rec in open_records:
        for item in rec.get("ai_inventory", []):
            impact = rec.get("ai_impact_assessment_draft") or {}
            ai_systems.append({**item, "pr": rec.get("pr"), "risk": impact.get("risk_level", ""),
                               "autonomy": impact.get("autonomy_level", "")})

    open_rows = [p for p in pr_rows if p["state"] == "OPEN"]
    return {
        "repo": repo,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "status_note": next((r.get("status_note") for r in reversed(records) if r.get("status_note")), ""),
        "kpis": {
            "prs_reviewed": len(pr_rows),
            "open_blocking": sum(1 for p in open_rows if p["verdict"] == "Blocking"),
            "critical": sum(p["severity"]["critical"] for p in open_rows),
            "high": sum(p["severity"]["high"] for p in open_rows),
            "kev": sum(p["kev"] for p in open_rows),
            "ai_systems": len(ai_systems),
        },
        "frameworks": frameworks,
        "prs": pr_rows,
        "controls": list(catalog.values()),
        "matrix": matrix,
        "agg": agg,
        "findings": findings[:25],
        "ai_systems": ai_systems,
    }


def render(data: dict) -> str:
    payload = json.dumps(data).replace("</", "<\\/")
    return TEMPLATE.replace("__DATA__", payload)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the AuditLens readiness dashboard")
    ap.add_argument("--evidence-dir", required=True)
    ap.add_argument("--prs", default=None, help="JSON from: gh pr list --state all --json number,title,state,url")
    ap.add_argument("--repo", default="")
    ap.add_argument("--out", default="site/index.html")
    args = ap.parse_args(argv)

    records = load_evidence(Path(args.evidence_dir))
    prs = {}
    if args.prs and Path(args.prs).exists():
        prs = {p["number"]: p for p in json.loads(Path(args.prs).read_text())}
    data = summarize(records, prs, args.repo)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(data))
    print(f"[auditlens] dashboard: {len(records)} evidence record(s) -> {out}")
    return 0


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuditLens · Readiness dashboard</title>
<style>
  :root {
    --page: #f4f3ef; --surface: #fcfcfb; --text: #0b0b0b; --text-2: #52514e; --muted: #898781;
    --grid: #e1e0d9; --border: rgba(11,11,11,0.10); --blue: #2a78d6;
    --good: #0ca30c; --good-text: #006300; --good-tint: rgba(12,163,12,0.14);
    --warning: #fab219; --serious: #ec835a; --critical: #d03b3b;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --page: #121211; --surface: #1a1a19; --text: #f0efec; --text-2: #c3c2b7; --muted: #898781;
      --grid: #2c2c2a; --border: rgba(255,255,255,0.10); --blue: #3987e5;
      --good-text: #4cc94c; --good-tint: rgba(12,163,12,0.22);
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--page); color: var(--text);
         font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif; }
  main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 64px; }
  header { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
  h1 { font-size: 22px; margin: 0; letter-spacing: -0.01em; }
  h1 span { color: var(--muted); font-weight: 500; }
  h2 { font-size: 15px; margin: 0 0 4px; }
  .sub { color: var(--text-2); font-size: 13px; margin: 0 0 16px; }
  .meta { color: var(--text-2); font-size: 12px; text-align: right; }
  .meta a { color: var(--text-2); }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }
  .kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }
  .kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
  .kpi .label { color: var(--text-2); font-size: 12px; }
  .kpi .value { font-size: 28px; font-weight: 650; letter-spacing: -0.02em; line-height: 1.2; }
  .kpi .hint { color: var(--muted); font-size: 12px; }
  .fw { display: grid; grid-template-columns: 120px 1fr 64px; align-items: center; gap: 12px; padding: 10px 0; border-top: 1px solid var(--grid); }
  .fw:first-of-type { border-top: 0; }
  .fw .name { font-weight: 600; }
  .track { height: 10px; background: var(--grid); border-radius: 4px; overflow: hidden; }
  .fill { height: 100%; background: var(--blue); border-radius: 4px; }
  .fw .pct { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
  .fw .detail { grid-column: 2 / 4; color: var(--text-2); font-size: 12px; margin-top: -6px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--text-2); font-weight: 500; font-size: 12px; padding: 8px 10px; border-bottom: 1px solid var(--grid); }
  td { padding: 9px 10px; border-bottom: 1px solid var(--grid); vertical-align: top; }
  tr:last-child td { border-bottom: 0; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  a { color: var(--blue); text-decoration: none; } a:hover { text-decoration: underline; }
  .pill { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; white-space: nowrap; }
  .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
  code { font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; color: var(--text-2); }
  .matrix-wrap { overflow-x: auto; }
  .matrix td, .matrix th { padding: 4px 6px; border-bottom: 1px solid var(--grid); }
  .matrix td.cid { white-space: nowrap; font-weight: 600; }
  .matrix td.ctitle { color: var(--text-2); min-width: 260px; }
  .matrix th.prcol { text-align: center; min-width: 64px; }
  .cell { width: 26px; height: 26px; border-radius: 4px; margin: 0 auto; display: flex; align-items: center; justify-content: center;
          font-size: 13px; font-weight: 700; cursor: default; }
  .s-fail { background: var(--critical); color: #fff; }
  .s-no_findings { background: var(--good-tint); color: var(--good-text); }
  .s-performed { background: var(--blue); color: #fff; }
  .s-not_applicable { color: var(--muted); }
  .legend { display: flex; gap: 18px; flex-wrap: wrap; margin: 4px 0 12px; font-size: 12px; color: var(--text-2); }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .legend .cell { width: 18px; height: 18px; font-size: 11px; margin: 0; }
  .note { color: var(--text-2); font-size: 12px; background: var(--page); border-radius: 8px; padding: 8px 12px; margin-top: 12px; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 860px) { .grid2 { grid-template-columns: 1fr; } }
  .empty { color: var(--muted); font-size: 13px; }
  #tip { position: fixed; pointer-events: none; background: var(--surface); color: var(--text); border: 1px solid var(--border);
         border-radius: 8px; padding: 8px 10px; font-size: 12px; box-shadow: 0 4px 16px rgba(0,0,0,0.12); max-width: 300px; display: none; z-index: 10; }
  footer { color: var(--muted); font-size: 12px; margin-top: 24px; }
</style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>AuditLens <span>· Readiness dashboard</span></h1>
      <div class="sub" id="repo"></div>
    </div>
    <div class="meta" id="updated"></div>
  </header>

  <section class="kpis" id="kpis"></section>

  <section class="card">
    <h2>Framework readiness</h2>
    <p class="sub">Share of in-scope controls with no open findings across open pull requests.</p>
    <div id="frameworks"></div>
  </section>

  <section class="card">
    <h2>Pull requests reviewed</h2>
    <p class="sub">Latest AuditLens review of each pull request.</p>
    <div id="prs"></div>
  </section>

  <section class="card">
    <h2>Control status by pull request</h2>
    <p class="sub">Each control from the common control framework, as evaluated on each change.</p>
    <div class="legend">
      <span><span class="cell s-fail">✕</span> Fail</span>
      <span><span class="cell s-no_findings">✓</span> No findings</span>
      <span><span class="cell s-performed">●</span> Performed</span>
      <span><span class="cell s-not_applicable">—</span> Not applicable</span>
    </div>
    <div class="matrix-wrap"><table class="matrix" id="matrix"></table></div>
    <div class="note" id="statusnote"></div>
  </section>

  <div class="grid2">
    <section class="card">
      <h2>Open critical &amp; high findings</h2>
      <p class="sub">Blocking issues to fix before merge.</p>
      <div id="findings"></div>
    </section>
    <section class="card">
      <h2>AI systems detected</h2>
      <p class="sub">Draft AI inventory (ISO 42001 A.4.2 · NIST AI RMF GOVERN 1.6).</p>
      <div id="ai"></div>
    </section>
  </div>

  <footer>Generated by AuditLens from per-PR evidence records. Readiness reflects automated change review only; it is not an audit opinion.</footer>
</main>
<div id="tip" role="tooltip"></div>

<script type="application/json" id="data">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById('data').textContent);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmtDate = s => { if (!s) return ''; const d = new Date(s); return isNaN(d) ? s : d.toLocaleString(undefined, {dateStyle:'medium', timeStyle:'short'}); };
const SEVCOL = {critical:'var(--critical)', high:'var(--serious)', medium:'var(--warning)', low:'var(--muted)'};
const VERDICT = {
  'Blocking': ['var(--critical)', '✕ Blocking'],
  'Needs attention': ['var(--serious)', '! Needs attention'],
  'Pass': ['var(--good)', '✓ Pass'],
};

document.getElementById('repo').innerHTML = D.repo ? `<a href="https://github.com/${esc(D.repo)}">${esc(D.repo)}</a>` : '';
document.getElementById('updated').textContent = 'Updated ' + fmtDate(D.generated_at);

const k = D.kpis;
const kpis = [
  ['Pull requests reviewed', k.prs_reviewed, 'latest review per PR'],
  ['Blocking open PRs', k.open_blocking, 'have a critical finding'],
  ['Critical findings', k.critical, `${k.high} high`],
  ['Exploited vulns (KEV)', k.kev, 'in CISA KEV catalog'],
  ['AI systems detected', k.ai_systems, 'need inventory + impact assessment'],
];
document.getElementById('kpis').innerHTML = kpis.map(([l, v, h]) =>
  `<div class="kpi"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div><div class="hint">${esc(h)}</div></div>`).join('');

document.getElementById('frameworks').innerHTML = D.frameworks.map(f => {
  if (f.pct === null) return `<div class="fw"><div class="name">${esc(f.name)}</div><div class="track"></div><div class="pct" style="color:var(--muted)">n/a</div>
    <div class="detail">No ${esc(f.name)} controls in scope for the open changes.</div></div>`;
  const refs = f.failing_refs.length ? ` · open: ${f.failing_refs.map(esc).join(', ')}` : '';
  return `<div class="fw" data-tip="${esc(f.name)}: ${f.clear} of ${f.in_scope} in-scope controls clear (${f.total} mapped)">
    <div class="name">${esc(f.name)}</div>
    <div class="track"><div class="fill" style="width:${f.pct}%"></div></div>
    <div class="pct">${f.pct}%</div>
    <div class="detail">${f.clear} of ${f.in_scope} in-scope controls clear${refs}</div></div>`;
}).join('');

const prs = D.prs;
document.getElementById('prs').innerHTML = prs.length ? `<table>
  <thead><tr><th>Pull request</th><th>Verdict</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th><th class="num">KEV</th><th>AI</th><th>Reviewed</th></tr></thead>
  <tbody>${prs.map(p => {
    const [col, label] = VERDICT[p.verdict];
    const closed = p.state !== 'OPEN' ? ` <span style="color:var(--muted);font-size:12px">(${esc(p.state.toLowerCase())})</span>` : '';
    return `<tr><td><a href="${esc(p.url)}">#${esc(p.number)} ${esc(p.title)}</a>${closed}<br><code>${esc(p.sha)}</code></td>
      <td><span class="pill"><span class="dot" style="background:${col}"></span>${esc(label)}</span></td>
      ${['critical','high','medium','low'].map(s => `<td class="num">${p.severity[s] || '<span style="color:var(--muted)">0</span>'}</td>`).join('')}
      <td class="num">${p.kev || '<span style="color:var(--muted)">0</span>'}</td>
      <td>${p.ai ? 'Yes' : '<span style="color:var(--muted)">No</span>'}</td>
      <td style="color:var(--text-2);white-space:nowrap">${esc(fmtDate(p.reviewed_at))}</td></tr>`;
  }).join('')}</tbody></table>` : '<p class="empty">No evidence records found yet.</p>';

const GLYPH = {fail:'✕', no_findings:'✓', performed:'●', not_applicable:'—'};
const LABEL = {fail:'Fail', no_findings:'No findings', performed:'Performed', not_applicable:'Not applicable'};
const cols = prs.map(p => String(p.number));
document.getElementById('matrix').innerHTML = `<thead><tr><th>Control</th><th></th>${prs.map(p =>
  `<th class="prcol"><a href="${esc(p.url)}">#${esc(p.number)}</a></th>`).join('')}</tr></thead><tbody>${
  D.controls.map(c => `<tr><td class="cid">${esc(c.id)}</td><td class="ctitle">${esc(c.title)}</td>${cols.map(n => {
    const v = (D.matrix[c.id] || {})[n] || {status:'not_applicable', count:0};
    const refs = Object.entries(c.frameworks).map(([fw, r]) => `${fw} ${r.join(', ')}`).join(' · ');
    const tip = `${c.id} on PR #${n}: ${LABEL[v.status] || v.status}${v.count ? ` (${v.count} finding${v.count > 1 ? 's' : ''})` : ''} — ${c.title}. ${refs}`;
    return `<td><div class="cell s-${esc(v.status)}" data-tip="${esc(tip)}" aria-label="${esc(tip)}">${GLYPH[v.status] || '?'}</div></td>`;
  }).join('')}</tr>`).join('')}</tbody>`;
document.getElementById('statusnote').textContent = D.status_note || '';

document.getElementById('findings').innerHTML = D.findings.length ? `<table><thead><tr><th>Severity</th><th>Finding</th><th>PR</th></tr></thead><tbody>${
  D.findings.map(f => `<tr><td><span class="pill"><span class="dot" style="background:${SEVCOL[f.severity]}"></span>${esc(f.severity)}</span></td>
    <td>${esc(f.title)}${f.llm_generated ? ' 🤖' : ''}<br><code>${esc(f.file || '')}${f.line ? ':' + f.line : ''}</code> · <code>${esc((f.control_ids || []).join(', '))}</code></td>
    <td class="num">#${esc(f.pr)}</td></tr>`).join('')}</tbody></table>` : '<p class="empty">No open critical or high findings.</p>';

document.getElementById('ai').innerHTML = D.ai_systems.length ? `<table><thead><tr><th>System</th><th>Provider / model</th><th>Risk</th><th>Controls</th></tr></thead><tbody>${
  D.ai_systems.map(a => `<tr><td><code>${esc(a.file)}</code><br><span style="color:var(--text-2);font-size:12px">PR #${esc(a.pr)}${a.autonomy ? ' · ' + esc(a.autonomy) : ''}</span></td>
    <td>${esc((a.providers || []).concat(a.vector_stores || []).join(', '))}<br><code>${esc((a.models || []).join(', ') || 'unknown')}</code></td>
    <td>${a.risk ? `<span class="pill"><span class="dot" style="background:${a.risk === 'high' ? 'var(--critical)' : a.risk === 'medium' ? 'var(--warning)' : 'var(--good)'}"></span>${esc(a.risk)}</span>` : '<span style="color:var(--muted)">—</span>'}</td>
    <td style="font-size:12px;color:var(--text-2)">Token limit ${a.has_token_limit ? '✓' : '✕'}<br>Logging ${a.has_logging ? '✓' : '✕'}</td></tr>`).join('')}</tbody></table>`
  : '<p class="empty">No AI components in open changes.</p>';

const tip = document.getElementById('tip');
document.addEventListener('mousemove', e => {
  const t = e.target.closest('[data-tip]');
  if (!t) { tip.style.display = 'none'; return; }
  tip.textContent = t.dataset.tip; tip.style.display = 'block';
  const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
  const y = Math.min(e.clientY + 14, window.innerHeight - tip.offsetHeight - 8);
  tip.style.left = x + 'px'; tip.style.top = y + 'px';
});
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
