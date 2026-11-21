"""Audit evidence: a JSON record per PR showing which controls were evaluated and their result.
Auditors ask "show me that changes are reviewed for security" — this is that proof."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .controls import ControlCatalog
from .models import Finding


def build_record(findings: list[Finding], cat: ControlCatalog, inventory: list[dict], dep_rows: list[dict],
                 impact: dict, meta: dict, warnings: list[str]) -> dict:
    failing = {c for f in findings for c in f.control_ids}
    scope = cat.in_scope(ai_detected=bool(inventory))
    controls = [{
        "id": cid,
        "title": cat.title(cid),
        "status": "fail" if cid in failing else "pass",
        "frameworks": cat.framework_refs([cid]),
        "finding_count": sum(1 for f in findings if cid in f.control_ids),
    } for cid in scope]
    return {
        "schema": "auditlens.evidence/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        **meta,
        "control_activity": "AL-08 security review performed on change before merge",
        "controls": controls,
        "findings": [f.to_dict() for f in findings],
        "dependencies": dep_rows,
        "ai_inventory": inventory,
        "ai_impact_assessment_draft": impact,
        "warnings": warnings,
    }


def write(record: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"evidence-{record.get('head_sha', 'local')[:12]}.json"
    path.write_text(json.dumps(record, indent=2))
    return path
