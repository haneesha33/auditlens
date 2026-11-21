"""Load the common control framework and resolve framework references."""
from __future__ import annotations

from pathlib import Path

import yaml

FRAMEWORK_LABELS = {
    "soc2": "SOC 2",
    "iso27001": "ISO 27001",
    "iso42001": "ISO 42001",
    "nist_ai_rmf": "NIST AI RMF",
    "owasp_llm": "OWASP LLM",
}

AI_CONTROL_PREFIX = "AL-2"   # AL-20..AL-30 are AI governance / AI security controls


class ControlCatalog:
    def __init__(self, path: Path):
        data = yaml.safe_load(Path(path).read_text())
        self.controls: dict[str, dict] = {c["id"]: c for c in data["controls"]}

    def valid(self, ids: list[str]) -> list[str]:
        return [i for i in ids if i in self.controls]

    def title(self, cid: str) -> str:
        return self.controls.get(cid, {}).get("title", cid)

    def policy(self, cid: str) -> str:
        return self.controls.get(cid, {}).get("policy", "")

    def framework_refs(self, ids: list[str]) -> dict[str, list[str]]:
        """Merge framework references for a set of controls: {'SOC 2': ['CC6.1'], ...}."""
        out: dict[str, list[str]] = {}
        for cid in ids:
            for fw, refs in self.controls.get(cid, {}).get("frameworks", {}).items():
                label = FRAMEWORK_LABELS.get(fw, fw)
                bucket = out.setdefault(label, [])
                for r in refs:
                    if r not in bucket:
                        bucket.append(r)
        return out

    def refs_inline(self, ids: list[str]) -> str:
        refs = self.framework_refs(ids)
        return "; ".join(f"{fw} {', '.join(r)}" for fw, r in refs.items())

    def in_scope(self, ai_detected: bool) -> list[str]:
        return [cid for cid in self.controls if ai_detected or not cid.startswith(AI_CONTROL_PREFIX)]

    def prompt_listing(self) -> str:
        """Compact listing for LLM prompts so the model can only cite real controls."""
        lines = []
        for cid, c in self.controls.items():
            lines.append(f"{cid}: {c['title']} [{c.get('policy', '')}] -> {self.refs_inline([cid])}")
        return "\n".join(lines)
