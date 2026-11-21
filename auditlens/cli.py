"""AuditLens entry point: python -m auditlens [options]"""
from __future__ import annotations

import argparse
import fnmatch
import os
import shutil
import sys
from datetime import date
from pathlib import Path

from . import agents, ai_checks, diff, evidence, github, llm, report, scanners, vulns
from .controls import ControlCatalog
from .models import SEVERITY_ORDER, dedupe, sort_findings

TOOL_ROOT = Path(__file__).resolve().parent.parent


def load_policies(policy_dir: Path) -> tuple[str, str]:
    """Return (all_policies_text, ai_policy_text)."""
    all_parts, ai_parts = [], []
    for p in sorted(policy_dir.glob("*.md")):
        text = f"=== {p.stem} ===\n{p.read_text()}"
        all_parts.append(text)
        if p.stem.startswith("ai") or "ai-" in p.stem:
            ai_parts.append(text)
    return "\n\n".join(all_parts), "\n\n".join(ai_parts or all_parts)


MAX_EXCEPTION_DAYS = 90


def load_exclusions(repo: Path, today: date | None = None) -> tuple[list[dict], list[str]]:
    """Read .auditlens/ignore, an exception register. Each line:
        <path or glob>  # <reason>; approved-by: <name>; expires: YYYY-MM-DD
    An entry is applied only if it has a reason, an approver and an expiry date that is
    not in the past and at most MAX_EXCEPTION_DAYS away. Invalid or expired entries are
    ignored (the files get scanned) and reported. Returns (rules, problems)."""
    path = repo / ".auditlens" / "ignore"
    if not path.exists():
        return [], []
    today = today or date.today()
    rules, problems = [], []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pattern, _, rest = line.partition("#")
        pattern = pattern.strip()
        parts = [p.strip() for p in rest.split(";")]
        reason = parts[0] if parts and ":" not in parts[0] else ""
        fields = {k.strip().lower(): v.strip() for k, _, v in (p.partition(":") for p in parts if ":" in p)}
        approver, expires_raw = fields.get("approved-by", ""), fields.get("expires", "")
        missing = [name for name, val in (("reason", reason), ("approved-by", approver), ("expires", expires_raw)) if not val]
        if missing:
            problems.append(f"line {n} ({pattern}): missing {', '.join(missing)}")
            continue
        try:
            expires = date.fromisoformat(expires_raw)
        except ValueError:
            problems.append(f"line {n} ({pattern}): expires '{expires_raw}' is not a YYYY-MM-DD date")
            continue
        if expires < today:
            problems.append(f"line {n} ({pattern}): expired on {expires} - renew it with a fresh approval or remove it")
            continue
        if (expires - today).days > MAX_EXCEPTION_DAYS:
            problems.append(f"line {n} ({pattern}): expires {expires}, more than {MAX_EXCEPTION_DAYS} days away")
            continue
        rules.append({"pattern": pattern, "reason": reason, "approved_by": approver,
                      "expires": expires.isoformat(), "files": []})
    return rules, problems


def is_excluded(f: str, rules: list[dict]) -> dict | None:
    for r in rules:
        p = r["pattern"]
        if fnmatch.fnmatch(f, p) or f.startswith(p.rstrip("/") + "/"):
            return r
    return None


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="auditlens", description="Compliance-aware PR review for SOC 2, ISO 27001, ISO 42001 and NIST AI RMF")
    ap.add_argument("--repo-path", default=os.environ.get("GITHUB_WORKSPACE", "."))
    ap.add_argument("--base", default=None, help="Base ref (default: origin/$GITHUB_BASE_REF or origin/main)")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--policies", default=None, help="Policy folder (default: <repo>/.auditlens/policies or bundled samples)")
    ap.add_argument("--controls", default=None, help="Controls YAML (default: <repo>/.auditlens/controls.yaml or bundled)")
    ap.add_argument("--output-dir", default="auditlens-out")
    ap.add_argument("--no-llm", action="store_true", help="Deterministic checks only")
    ap.add_argument("--offline", action="store_true", help="Skip all network calls (OSV/KEV/EPSS/LLM/GitHub)")
    ap.add_argument("--dry-run", action="store_true", help="Print the report instead of commenting on the PR")
    ap.add_argument("--fail-on", default="critical", choices=["critical", "high", "medium", "low", "never"])
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    repo = Path(args.repo_path).resolve()
    base = args.base or (f"origin/{os.environ['GITHUB_BASE_REF']}" if os.environ.get("GITHUB_BASE_REF") else "origin/main")
    head = args.head

    policy_dir = Path(args.policies) if args.policies else (
        repo / ".auditlens/policies" if (repo / ".auditlens/policies").is_dir() else TOOL_ROOT / "policies")
    controls_path = Path(args.controls) if args.controls else (
        repo / ".auditlens/controls.yaml" if (repo / ".auditlens/controls.yaml").exists() else TOOL_ROOT / "controls/controls.yaml")

    catalog = ControlCatalog(controls_path)
    policies_text, ai_policy_text = load_policies(policy_dir)
    warnings: list[str] = []
    checks: list[str] = []

    files = diff.changed_files(repo, base, head)
    added = diff.added_lines(repo, base, head)
    exclusions, exclusion_problems = load_exclusions(repo)
    if exclusion_problems:
        warnings.append("Invalid .auditlens/ignore entries were NOT applied (those files were scanned): "
                        + "; ".join(exclusion_problems))
    if exclusions:
        kept = []
        for f in files:
            rule = is_excluded(f, exclusions)
            if rule:
                rule["files"].append(f)
            else:
                kept.append(f)
        files = kept
        added = {f: v for f, v in added.items() if f in set(files)}
        skipped = sum(len(r["files"]) for r in exclusions)
        if skipped:
            warnings.append(f"{skipped} changed file(s) excluded by .auditlens/ignore: "
                            + "; ".join(f"{', '.join(r['files'])} ({r['reason']}; approved by {r['approved_by']}, "
                                        f"expires {r['expires']})" for r in exclusions if r["files"]))
    sha = diff.head_sha(repo, head)
    print(f"[auditlens] {len(files)} changed file(s) between {base} and {head}", file=sys.stderr)

    findings = []
    # 1. Deterministic scanners
    findings += ai_checks.scan_secrets(added); checks.append("secrets")
    findings += scanners.run_basic_checks(added); checks.append("builtin-rules")
    findings += scanners.run_semgrep(repo, files, warnings)
    if shutil.which("semgrep"):
        checks.append("semgrep")
    findings += scanners.run_checkov(repo, files, warnings)
    if shutil.which("checkov"):
        checks.append("checkov")

    # 2. Dependency risk
    dep_rows, upgrades = [], []
    deps = vulns.parse_new_dependencies(repo, added)
    if deps and not args.offline:
        dep_findings, dep_rows = vulns.scan_dependencies(deps, warnings)
        upgrades = vulns.recommend_upgrades(dep_rows)
        findings += dep_findings
        checks.append("osv+kev+epss")
    elif deps:
        warnings.append(f"Offline mode: {len(deps)} new dependencies not checked.")

    # 3. AI detection + deterministic AI security checks
    inventory = ai_checks.detect_ai_systems(repo, files)
    if inventory:
        findings += ai_checks.scan_ai_risks(added, inventory)
        findings += ai_checks.governance_actions(inventory)
        checks.append("ai-security")

    # 4. LLM agents (grounded + validated)
    impact = {}
    use_llm = not args.no_llm and not args.offline
    if use_llm and not llm.available():
        warnings.append("ANTHROPIC_API_KEY not set: policy and AI governance agents skipped.")
        use_llm = False
    if use_llm and files:
        unified = diff.unified_diff(repo, base, head, exclude=[r["pattern"] for r in exclusions])
        changed = set(files)
        try:
            findings += agents.policy_agent(unified, policies_text, catalog, findings, changed)
            checks.append("policy-agent")
        except Exception as e:  # noqa: BLE001
            warnings.append(f"Policy agent failed: {e}")
        if inventory:
            try:
                ai_f, impact = agents.ai_governance_agent(unified, ai_policy_text, catalog, inventory, findings, changed)
                findings += ai_f
                checks.append("ai-governance-agent")
            except Exception as e:  # noqa: BLE001
                warnings.append(f"AI governance agent failed: {e}")

    findings = sort_findings(dedupe(scanners.merge_iac_overlaps(findings)))
    meta = {"repository": os.environ.get("GITHUB_REPOSITORY", repo.name), "pr": github.pr_number_from_event(),
            "base": base, "head_sha": sha, "changed_files": files, "checks": checks}

    body = report.render(findings, catalog, dep_rows, inventory, impact, warnings, meta, upgrades)
    iac_changed = any(f.endswith(".tf") or any(h in f.lower() for h in scanners.IAC_HINTS) for f in files)
    record = evidence.build_record(findings, catalog, inventory, dep_rows, impact, meta, warnings,
                                   iac_changed=iac_changed, deps_changed=bool(deps),
                                   upgrades=upgrades, exclusions=[r for r in exclusions if r["files"]])
    out_dir = Path(args.output_dir)
    ev_path = evidence.write(record, out_dir)
    (out_dir / "report.md").write_text(body)
    print(f"[auditlens] evidence written to {ev_path}", file=sys.stderr)

    token, repo_name, pr = os.environ.get("GITHUB_TOKEN"), os.environ.get("GITHUB_REPOSITORY"), meta["pr"]
    if args.dry_run or args.offline or not (token and repo_name and pr):
        print(body)
    else:
        try:
            print(f"[auditlens] PR comment {github.upsert_comment(repo_name, pr, body, token)}", file=sys.stderr)
        except Exception as e:  # noqa: BLE001
            print(f"[auditlens] could not comment on PR: {e}", file=sys.stderr)
            print(body)

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 9) <= threshold for f in findings):
            print(f"[auditlens] failing: findings at or above '{args.fail_on}'", file=sys.stderr)
            return 1
    return 0
