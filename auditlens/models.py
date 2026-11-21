"""Shared data model for AuditLens findings."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    title: str
    severity: str                 # critical | high | medium | low | info
    source: str                   # semgrep | checkov | ai-check | secrets | dependency | policy-agent | ai-governance-agent
    control_ids: list[str] = field(default_factory=list)
    file: str | None = None
    line: int | None = None
    detail: str = ""
    fix: str = ""
    category: str = "security"    # security | ai-security | governance | dependency
    llm_generated: bool = False

    def key(self) -> tuple:
        # Same location + same controls = same issue, even if two scanners word it differently.
        # Dependencies are the exception: one package line can carry many distinct CVEs.
        if self.source == "dependency":
            return (self.file, self.title)
        if self.file and self.line:
            return (self.file, self.line, tuple(sorted(self.control_ids)))
        return (self.file, self.line, tuple(sorted(self.control_ids)), self.title.lower()[:40])

    def to_dict(self) -> dict:
        return asdict(self)


def risk_key(severity: str, detail: str) -> tuple:
    """Within a severity, put actively exploited (CISA KEV) issues first, then higher EPSS."""
    import re
    kev = 0 if "In CISA KEV" in (detail or "") else 1
    m = re.search(r"EPSS ([0-9.]+)%", detail or "")
    epss = -float(m.group(1)) if m else 0.0
    return (SEVERITY_ORDER.get(severity, 9), kev, epss)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (*risk_key(f.severity, f.detail), f.file or "", f.line or 0))


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = f.key()
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
