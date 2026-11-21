"""Audit evidence: a JSON record per PR showing which controls were evaluated and their result.
Auditors ask "show me that changes are reviewed for security": this is that proof.

Status values are deliberately conservative, because evidence must not overstate assurance:
  fail            automated checks found at least one issue for this control
  no_findings     the control was in scope and nothing was detected (not proof it operates)
  not_applicable  the change didn't touch anything this control covers
  performed       the control activity itself (AL-08: security review before merge) happened
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .controls import ControlCatalog
from .models import Finding

REVIEW_CONTROL = "AL-08"
IAC_CONTROLS = {"AL-03", "AL-05", "AL-12"}
DEPENDENCY_CONTROLS = {"AL-10", "AL-11"}
AI_PREFIX = "AL-2"
AI_EXTRA = {"AL-30"}  # retrieval / vector store control
RAG_CONTROL = "AL-30"

STATUS_NOTE = ("'no_findings' means automated checks detected no issue for this change; "
               "it is not proof the control operates effectively.")


def _status(cid: str, failing: set[str], iac_changed: bool, deps_changed: bool, ai_detected: bool,
            vector_store: bool = False) -> str:
    if cid in failing:
        return "fail"
    if cid == REVIEW_CONTROL:
        return "performed"
    if cid in IAC_CONTROLS and not iac_changed:
        return "not_applicable"
    if cid in DEPENDENCY_CONTROLS and not deps_changed:
        return "not_applicable"
    if (cid.startswith(AI_PREFIX) or cid in AI_EXTRA) and not ai_detected:
        return "not_applicable"
    if cid == RAG_CONTROL and not vector_store:
        return "not_applicable"   # AI present, but no retrieval / vector store in this change
    return "no_findings"


def build_record(findings: list[Finding], cat: ControlCatalog, inventory: list[dict], dep_rows: list[dict],
                 impact: dict, meta: dict, warnings: list[str],
                 iac_changed: bool = False, deps_changed: bool = False,
                 upgrades: list[dict] | None = None, exclusions: list[dict] | None = None) -> dict:
    failing = {c for f in findings for c in f.control_ids}
    controls = [{
        "id": cid,
        "title": cat.title(cid),
        "status": _status(cid, failing, iac_changed, deps_changed, bool(inventory),
                          any(i.get("vector_stores") for i in inventory)),
        "frameworks": cat.framework_refs([cid]),
        "finding_count": sum(1 for f in findings if cid in f.control_ids),
    } for cid in cat.controls]
    return {
        "schema": "auditlens.evidence/v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **meta,
        "control_activity": "AL-08 security review performed on change before merge",
        "status_note": STATUS_NOTE,
        "controls": controls,
        "findings": [f.to_dict() for f in findings],
        "dependencies": dep_rows,
        "upgrade_recommendations": upgrades or [],
        "excluded_paths": exclusions or [],
        "ai_inventory": inventory,
        "ai_impact_assessment_draft": impact,
        "warnings": warnings,
    }


def write(record: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"evidence-{record.get('head_sha', 'local')[:12]}.json"
    path.write_text(json.dumps(record, indent=2))
    return path
