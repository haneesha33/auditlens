"""LLM agents. Each has one job, a fixed output schema, and is grounded in the diff,
the written policies and the control catalog. Output is validated before use:
unknown control IDs and files outside the change are dropped."""
from __future__ import annotations

import json

from . import llm
from .controls import ControlCatalog
from .models import Finding

FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string", "description": "Short, specific issue title"},
        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "file": {"type": "string"},
        "line": {"type": "integer"},
        "control_ids": {"type": "array", "items": {"type": "string"}},
        "policy_quote": {"type": "string", "description": "Exact sentence from the policy that is violated"},
        "evidence": {"type": "string", "description": "The code that shows the issue"},
        "fix": {"type": "string", "description": "Concrete fix a developer can apply"},
    },
    "required": ["title", "severity", "file", "control_ids", "policy_quote", "evidence", "fix"],
}

GROUNDING_RULES = """Rules:
- Report only issues directly evidenced by ADDED lines in the diff. No speculation, no generic advice.
- Every finding must quote the exact policy sentence it violates and cite control IDs ONLY from the catalog.
- Do not repeat issues already listed under EXISTING FINDINGS.
- If nothing is wrong, return an empty findings list. Fewer, accurate findings beat many weak ones."""


def _validate(raw: list[dict], catalog: ControlCatalog, changed: set[str], source: str, category: str) -> list[Finding]:
    out = []
    for r in raw:
        ids = catalog.valid(r.get("control_ids", []))
        if not ids or r.get("file") not in changed:
            continue
        out.append(Finding(
            title=r["title"][:160], severity=r.get("severity", "medium"), source=source,
            control_ids=ids, file=r["file"], line=r.get("line"),
            detail=f"Policy: \"{r.get('policy_quote', '')[:300]}\" · Evidence: `{r.get('evidence', '')[:200]}`",
            fix=r.get("fix", "")[:400], category=category, llm_generated=True,
        ))
    return out


def _existing(findings: list[Finding]) -> str:
    return "\n".join(f"- {f.file}:{f.line} {f.title} {f.control_ids}" for f in findings) or "(none)"


def policy_agent(diff: str, policies: str, catalog: ControlCatalog, existing: list[Finding],
                 changed: set[str]) -> list[Finding]:
    system = ("You are a senior security compliance reviewer. You compare code changes against the company's "
              "written security policies and map violations to controls so developers understand what to fix and why.")
    user = f"""COMPANY POLICIES:
{policies}

CONTROL CATALOG (id: title [policy] -> framework refs):
{catalog.prompt_listing()}

EXISTING FINDINGS (from deterministic scanners):
{_existing(existing)}

PULL REQUEST DIFF:
{diff}

{GROUNDING_RULES}
Focus on non-AI policy issues: access control, authentication/authorization on new endpoints, data handling, logging, secure coding, infrastructure, vendors."""
    schema = {"type": "object", "properties": {"findings": {"type": "array", "items": FINDING_SCHEMA}},
              "required": ["findings"]}
    result = llm.structured_call(system, user, "report_policy_findings",
                                 "Report policy violations found in the diff.", schema)
    return _validate(result.get("findings", []), catalog, changed, "policy-agent", "security")


def ai_governance_agent(diff: str, ai_policy: str, catalog: ControlCatalog, inventory: list[dict],
                        existing: list[Finding], changed: set[str]) -> tuple[list[Finding], dict]:
    system = ("You are an AI security and AI governance specialist (ISO/IEC 42001, NIST AI RMF, OWASP Top 10 for LLM "
              "Applications). You review AI features in code changes for security risk and draft governance records.")
    user = f"""AI POLICY:
{ai_policy}

CONTROL CATALOG:
{catalog.prompt_listing()}

DETECTED AI COMPONENTS:
{json.dumps(inventory, indent=2)}

EXISTING FINDINGS:
{_existing(existing)}

PULL REQUEST DIFF:
{diff}

Tasks:
1. Find AI security issues in ADDED lines that existing findings missed (prompt injection paths, sensitive data to models,
   unsafe output handling, excessive agency, RAG access control, system prompt leakage, unbounded consumption).
2. Draft an AI impact assessment for the AI functionality in this change, based only on what the code shows.
   Where the code does not tell you something, write "Unknown — owner to confirm".
{GROUNDING_RULES}"""
    schema = {
        "type": "object",
        "properties": {
            "findings": {"type": "array", "items": FINDING_SCHEMA},
            "impact_assessment": {
                "type": "object",
                "properties": {
                    "system_name": {"type": "string"},
                    "purpose": {"type": "string"},
                    "model_providers": {"type": "array", "items": {"type": "string"}},
                    "data_sent_to_model": {"type": "array", "items": {"type": "string"}},
                    "affected_individuals": {"type": "array", "items": {"type": "string"}},
                    "autonomy_level": {"type": "string", "enum": ["informational", "human-in-the-loop", "autonomous"]},
                    "potential_harms": {"type": "array", "items": {"type": "string"}},
                    "mitigations_present": {"type": "array", "items": {"type": "string"}},
                    "mitigations_needed": {"type": "array", "items": {"type": "string"}},
                    "risk_level": {"type": "string", "enum": ["low", "medium", "high"]},
                    "risk_rationale": {"type": "string"},
                },
                "required": ["system_name", "purpose", "model_providers", "data_sent_to_model", "affected_individuals",
                             "autonomy_level", "potential_harms", "mitigations_present", "mitigations_needed",
                             "risk_level", "risk_rationale"],
            },
        },
        "required": ["findings", "impact_assessment"],
    }
    result = llm.structured_call(system, user, "report_ai_review",
                                 "Report AI security findings and a draft AI impact assessment.", schema, max_tokens=5000)
    findings = _validate(result.get("findings", []), catalog, changed, "ai-governance-agent", "ai-security")
    return findings, result.get("impact_assessment", {})
