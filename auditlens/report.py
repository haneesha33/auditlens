"""Render the PR comment (Markdown)."""
from __future__ import annotations

from .controls import ControlCatalog
from .models import Finding, sort_findings

MARKER = "<!-- auditlens-report -->"
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
MAX_COMMENT = 60000


def verdict(findings: list[Finding]) -> tuple[str, str]:
    sev = {f.severity for f in findings}
    if "critical" in sev:
        return "❌ Blocking", "Critical issues must be fixed before merge."
    if "high" in sev:
        return "⚠️ Needs attention", "High-risk issues found. Fix or document an approved exception."
    if findings:
        return "✅ Pass with notes", "No blocking issues. Review the notes below."
    return "✅ Pass", "No policy or control issues found in this change."


def _loc(f: Finding) -> str:
    if not f.file:
        return "—"
    return f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"


def _row(f: Finding, cat: ControlCatalog) -> str:
    bot = " 🤖" if f.llm_generated else ""
    controls = ", ".join(f.control_ids)
    refs = cat.refs_inline(f.control_ids)
    title = f.title.replace("|", "\\|")
    detail = (f.detail or "").replace("|", "\\|").replace("\n", " ")
    fix = (f.fix or "").replace("|", "\\|").replace("\n", " ")
    return (f"| {SEV_ICON.get(f.severity, '')} {f.severity} | **{title}**{bot}<br><sub>{detail}</sub> | {_loc(f)} "
            f"| **{controls}**<br><sub>{refs}</sub> | {fix} |")


def _table(findings: list[Finding], cat: ControlCatalog) -> list[str]:
    lines = ["| Severity | Finding | Location | Controls | Fix |", "|---|---|---|---|---|"]
    lines += [_row(f, cat) for f in sort_findings(findings)]
    return lines


def render(findings: list[Finding], cat: ControlCatalog, dep_rows: list[dict], inventory: list[dict],
           impact: dict, warnings: list[str], meta: dict) -> str:
    title, summary = verdict(findings)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low")}
    failing = sorted({c for f in findings for c in f.control_ids})
    fw_impact = cat.framework_refs(failing)

    out = [MARKER, f"## 🔍 AuditLens Compliance Review — {title}", "", summary, ""]
    out.append(" · ".join(f"{SEV_ICON[s]} {counts[s]} {s}" for s in counts))
    out.append("")

    if fw_impact:
        out += ["### Framework impact", "| Framework | Affected requirements |", "|---|---|"]
        out += [f"| {fw} | {', '.join(refs)} |" for fw, refs in fw_impact.items()]
        out.append("")

    security = [f for f in findings if f.category in ("security", "dependency")]
    ai = [f for f in findings if f.category == "ai-security"]
    gov = [f for f in findings if f.category == "governance"]

    if security:
        out += ["### 🛡️ Security & policy findings", *_table(security, cat), ""]
    if ai:
        out += ["### 🤖 AI security findings (OWASP LLM Top 10)", *_table(ai, cat), ""]

    if dep_rows:
        out += ["### 📦 Dependency risk (OSV + CISA KEV + EPSS)",
                "| Package | Vulnerability | KEV | EPSS | Priority | Fixed in |", "|---|---|---|---|---|---|"]
        for r in sorted(dep_rows, key=lambda r: (not r["kev"], -r["epss"])):
            out.append(f"| `{r['package']}` | {r['vuln']} | {'🚨 Yes' if r['kev'] else 'No'} | {r['epss']:.2%} "
                       f"| {SEV_ICON[r['severity']]} {r['severity']} | {', '.join(r['fixed']) or '—'} |")
        out.append("")

    if inventory or gov:
        out += ["### 🏛️ AI governance (ISO 42001 · NIST AI RMF)"]
        if gov:
            out += ["**Required actions before production:**"]
            out += [f"- [ ] {f.title} — *{', '.join(f.control_ids)}: {cat.refs_inline(f.control_ids)}*" for f in gov]
            out.append("")
        if inventory:
            out += ["<details><summary><b>Draft AI inventory entries</b></summary>", "",
                    "| File | Providers | Vector stores | Models | Token limit | Logging |", "|---|---|---|---|---|---|"]
            for i in inventory:
                out.append(f"| `{i['file']}` | {', '.join(i['providers']) or '—'} | {', '.join(i['vector_stores']) or '—'} "
                           f"| {', '.join(i['models']) or 'Unknown'} | {'✅' if i['has_token_limit'] else '❌'} "
                           f"| {'✅' if i['has_logging'] else '❌'} |")
            out += ["", "</details>", ""]
        if impact:
            out += ["<details><summary><b>Draft AI impact assessment 🤖 (owner to review)</b></summary>", ""]
            out.append(f"**System:** {impact.get('system_name', '')}  ")
            out.append(f"**Purpose:** {impact.get('purpose', '')}  ")
            out.append(f"**Autonomy:** {impact.get('autonomy_level', '')} · **Risk level:** {impact.get('risk_level', '').upper()}  ")
            out.append(f"**Rationale:** {impact.get('risk_rationale', '')}")
            for key, label in [("model_providers", "Model providers"), ("data_sent_to_model", "Data sent to model"),
                               ("affected_individuals", "Affected individuals"), ("potential_harms", "Potential harms"),
                               ("mitigations_present", "Mitigations present"), ("mitigations_needed", "Mitigations needed")]:
                items = impact.get(key) or []
                if items:
                    out.append(f"\n**{label}:**")
                    out += [f"- {x}" for x in items]
            out += ["", "</details>", ""]

    if warnings:
        out += ["<details><summary>Run notes</summary>", ""] + [f"- {w}" for w in warnings] + ["", "</details>", ""]

    out += ["---",
            f"<sub>AuditLens · commit `{meta.get('head_sha', '')[:7]}` · checks: {', '.join(meta.get('checks', []))} · "
            "🤖 = AI-generated, grounded in your policies; verify before acting. "
            "Evidence record saved as a workflow artifact.</sub>"]

    body = "\n".join(out)
    if len(body) > MAX_COMMENT:
        body = body[:MAX_COMMENT] + "\n\n_…truncated. Full results are in the evidence artifact._"
    return body
