"""Deterministic scanners: Semgrep (code) and Checkov (infrastructure as code).

Both are optional. If a scanner isn't installed, AuditLens records a warning and continues.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import Finding

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".cs"}
IAC_EXT = {".tf", ".yaml", ".yml", ".json"}
IAC_HINTS = ("terraform", "infra", "k8s", "kubernetes", "helm", "cloudformation", "deploy")

SEMGREP_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
CHECKOV_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _semgrep_controls(check_id: str, message: str) -> list[str]:
    t = f"{check_id} {message}".lower()
    if any(k in t for k in ("secret", "hardcoded", "password", "api-key", "token")):
        return ["AL-01"]
    if any(k in t for k in ("crypto", "ssl", "tls", "md5", "sha1", "cipher")):
        return ["AL-04"]
    if any(k in t for k in ("auth", "csrf", "jwt")):
        return ["AL-02"]
    if any(k in t for k in ("log", "logging")):
        return ["AL-09"]
    return ["AL-07"]


def _checkov_controls(check_id: str, name: str) -> list[str]:
    t = f"{check_id} {name}".lower()
    ids = []
    if "encrypt" in t or "kms" in t or "tls" in t or "https" in t:
        ids.append("AL-04")
    if "public" in t or "0.0.0.0" in t or "ingress" in t or "acl" in t:
        ids.append("AL-05")
    if "logging" in t or "log " in t or "access log" in t:
        ids.append("AL-09")
    if "iam" in t or "privilege" in t or "wildcard" in t or "*" in t or "admin" in t:
        ids.append("AL-03")
    return ids or ["AL-12"]


BASIC_RULES = [
    # (file suffixes, regex, title, severity, controls, fix)
    (CODE_EXT, r"""\.execute\(\s*(f["']|["'][^"']*["']\s*(%|\+|\.format))""",
     "SQL query built with string interpolation", "high", ["AL-07"],
     "Use parameterized queries (placeholders + bound parameters)."),
    (CODE_EXT, r"(subprocess\.\w+\(.*shell\s*=\s*True|os\.system\(|os\.popen\()",
     "Shell command execution with shell=True / os.system", "high", ["AL-07"],
     "Pass an argument list without shell=True and validate inputs against an allow-list."),
    (CODE_EXT, r"(verify\s*=\s*False|ssl\._create_unverified_context|rejectUnauthorized:\s*false)",
     "TLS certificate verification disabled", "high", ["AL-04"],
     "Keep certificate verification on; fix the trust store instead."),
    ({".tf"}, r"""(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false|acl\s*=\s*"public-read""",
     "Storage bucket allows public access", "critical", ["AL-05"],
     "Enable all four S3 public access block settings and remove public ACLs."),
    ({".tf"}, r"""(Action\s*=\s*"\*"|"Action"\s*:\s*"\*"|actions\s*=\s*\["\*"\])""",
     "IAM policy grants wildcard actions", "high", ["AL-03"],
     "Grant only the specific actions and resources this role needs."),
    ({".tf"}, r"""cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]""",
     "Network rule open to the internet (0.0.0.0/0)", "high", ["AL-05"],
     "Restrict ingress to known CIDR ranges or a load balancer security group."),
]


def run_basic_checks(added: dict[str, list[tuple[int, str]]]) -> list[Finding]:
    """Lightweight built-in rules so core issues are caught even when Semgrep/Checkov aren't available."""
    import re
    findings, seen_iac = [], set()
    for path, lines in added.items():
        suffix = Path(path).suffix
        for ln, text in lines:
            for exts, pat, title, sev, controls, fix in BASIC_RULES:
                if suffix in exts and re.search(pat, text):
                    if suffix == ".tf":            # one finding per IaC rule per file
                        if (path, title) in seen_iac:
                            continue
                        seen_iac.add((path, title))
                    findings.append(Finding(title=title, severity=sev, source="builtin-rules", control_ids=controls,
                                            file=path, line=ln, detail=f"`{text.strip()[:160]}`", fix=fix))
    return findings


def run_semgrep(repo: Path, files: list[str], warnings: list[str]) -> list[Finding]:
    targets = [f for f in files if Path(f).suffix in CODE_EXT and (repo / f).exists()]
    if not targets:
        return []
    if not shutil.which("semgrep"):
        warnings.append("Semgrep not installed: code pattern scan skipped.")
        return []
    cmd = ["semgrep", "scan", "--config", "p/default", "--json", "--quiet", "--metrics", "off", *targets]
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        warnings.append(f"Semgrep output could not be parsed: {proc.stderr[:300]}")
        return []
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        msg = extra.get("message", "").strip()
        findings.append(Finding(
            title=msg.split(".")[0][:140] or r.get("check_id", "Semgrep finding"),
            severity=SEMGREP_SEV.get(extra.get("severity", "WARNING"), "medium"),
            source="semgrep",
            control_ids=_semgrep_controls(r.get("check_id", ""), msg),
            file=r.get("path"),
            line=r.get("start", {}).get("line"),
            detail=f"Rule `{r.get('check_id')}`: {msg[:400]}",
            fix=(extra.get("fix") or "See rule guidance."),
        ))
    return findings


def run_checkov(repo: Path, files: list[str], warnings: list[str]) -> list[Finding]:
    targets = [
        f for f in files
        if (repo / f).exists() and (
            f.endswith(".tf") or (Path(f).suffix in IAC_EXT and any(h in f.lower() for h in IAC_HINTS))
        )
    ]
    if not targets:
        return []
    if not shutil.which("checkov"):
        warnings.append("Checkov not installed: infrastructure-as-code scan skipped.")
        return []
    cmd = ["checkov", "--quiet", "--compact", "-o", "json"]
    for t in targets:
        cmd += ["-f", t]
    proc = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        warnings.append(f"Checkov output could not be parsed: {proc.stderr[:300]}")
        return []
    reports = data if isinstance(data, list) else [data]
    findings = []
    for rep in reports:
        for c in rep.get("results", {}).get("failed_checks", []):
            name = c.get("check_name", "Checkov finding")
            fpath = (c.get("file_path") or "").lstrip("/")
            line_range = c.get("file_line_range") or [None]
            findings.append(Finding(
                title=name[:140],
                severity=CHECKOV_SEV.get((c.get("severity") or "").upper(), "high"),
                source="checkov",
                control_ids=_checkov_controls(c.get("check_id", ""), name),
                file=fpath or None,
                line=line_range[0],
                detail=f"Check `{c.get('check_id')}` failed on resource `{c.get('resource')}`.",
                fix=c.get("guideline") or "Apply the hardened baseline for this resource.",
                category="security",
            ))
    return findings
