"""AuditLens entry point: python -m auditlens [options]"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
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
    dep_rows = []
    deps = vulns.parse_new_dependencies(repo, added)
    if deps and not args.offline:
        dep_findings, dep_rows = vulns.scan_dependencies(deps, warnings)
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
        unified = diff.unified_diff(repo, base, head)
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

    findings = sort_findings(dedupe(findings))
    meta = {"repository": os.environ.get("GITHUB_REPOSITORY", repo.name), "pr": github.pr_number_from_event(),
            "base": base, "head_sha": sha, "changed_files": files, "checks": checks}

    body = report.render(findings, catalog, dep_rows, inventory, impact, warnings, meta)
    iac_changed = any(f.endswith(".tf") or any(h in f.lower() for h in scanners.IAC_HINTS) for f in files)
    record = evidence.build_record(findings, catalog, inventory, dep_rows, impact, meta, warnings,
                                   iac_changed=iac_changed, deps_changed=bool(deps))
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
