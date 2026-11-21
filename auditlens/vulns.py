"""Dependency risk: OSV.dev for known vulnerabilities, CISA KEV for active exploitation,
FIRST EPSS for exploit likelihood. None of these APIs need a key."""
from __future__ import annotations

import json
import re
from pathlib import Path

from .http import request_json
from .models import Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss?cve={cves}"

EPSS_CRITICAL = 0.10   # matches Secure SDLC Policy §6.2
MAX_VULN_DETAILS = 25

REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+!]+)")
NPM_RE = re.compile(r'^\s*"(@?[A-Za-z0-9_.\-/]+)"\s*:\s*"[\^~>=<\s]*(\d[A-Za-z0-9_.\-+]*)"')
POM_DEP_RE = re.compile(r"<dependency>(.*?)</dependency>", re.S)


def _tag(block: str, tag: str) -> str | None:
    m = re.search(rf"<{tag}>\s*([^<\s]+)\s*</{tag}>", block)
    return m.group(1) if m else None


def parse_new_dependencies(repo: Path, added: dict[str, list[tuple[int, str]]]) -> list[dict]:
    deps = []
    for path, lines in added.items():
        name = Path(path).name
        if re.match(r"requirements.*\.txt$", name):
            for ln, text in lines:
                m = REQ_RE.match(text)
                if m:
                    pkg = m.group(1).split("[")[0]
                    deps.append({"name": pkg, "version": m.group(2), "ecosystem": "PyPI", "file": path, "line": ln})
        elif name == "package.json":
            for ln, text in lines:
                m = NPM_RE.match(text)
                if m and m.group(1) not in {"version", "name", "node", "npm"}:
                    deps.append({"name": m.group(1), "version": m.group(2), "ecosystem": "npm", "file": path, "line": ln})
        elif name == "pom.xml":
            content = (repo / path).read_text(errors="ignore") if (repo / path).exists() else ""
            added_text = "\n".join(t for _, t in lines)
            line_of = {t.strip(): ln for ln, t in lines}
            for block in POM_DEP_RE.findall(content):
                g, a, v = _tag(block, "groupId"), _tag(block, "artifactId"), _tag(block, "version")
                if g and a and v and not v.startswith("$") and (a in added_text or v in added_text):
                    ln = line_of.get(f"<artifactId>{a}</artifactId>")
                    deps.append({"name": f"{g}:{a}", "version": v, "ecosystem": "Maven", "file": path, "line": ln})
    return deps


def _load_kev(warnings: list[str]) -> dict[str, dict]:
    try:
        data = request_json(KEV_FEED, timeout=45)
        return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
    except Exception as e:  # noqa: BLE001
        warnings.append(f"CISA KEV feed unavailable ({e}); KEV check skipped.")
        return {}


def _load_epss(cves: list[str], warnings: list[str]) -> dict[str, float]:
    if not cves:
        return {}
    try:
        data = request_json(EPSS_API.format(cves=",".join(cves[:100])))
        return {row["cve"]: float(row["epss"]) for row in data.get("data", [])}
    except Exception as e:  # noqa: BLE001
        warnings.append(f"EPSS API unavailable ({e}); EPSS scoring skipped.")
        return {}


def _fixed_versions(vuln: dict) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []):
        for rng in aff.get("ranges", []):
            for ev in rng.get("events", []):
                # Skip git commit hashes (40 hex chars); developers need version numbers.
                if "fixed" in ev and ev["fixed"] not in fixed and not re.fullmatch(r"[0-9a-f]{40}", ev["fixed"]):
                    fixed.append(ev["fixed"])
    return fixed


def scan_dependencies(deps: list[dict], warnings: list[str]) -> tuple[list[Finding], list[dict]]:
    """Return (findings, dependency_table_rows)."""
    if not deps:
        return [], []
    try:
        batch = request_json(OSV_BATCH, method="POST", body={"queries": [
            {"package": {"name": d["name"], "ecosystem": d["ecosystem"]}, "version": d["version"]} for d in deps
        ]})
    except Exception as e:  # noqa: BLE001
        warnings.append(f"OSV.dev unavailable ({e}); dependency scan skipped.")
        return [], []

    # Collect vuln IDs per dependency, then fetch details (aliases -> CVE, severity, fixes).
    per_dep: list[tuple[dict, list[str]]] = []
    for dep, res in zip(deps, batch.get("results", [])):
        ids = [v["id"] for v in res.get("vulns", [])]
        if ids:
            per_dep.append((dep, ids))

    details: dict[str, dict] = {}
    for _, ids in per_dep:
        for vid in ids:
            if vid not in details and len(details) < MAX_VULN_DETAILS:
                try:
                    details[vid] = request_json(OSV_VULN.format(id=vid))
                except Exception as e:  # noqa: BLE001
                    warnings.append(f"OSV detail fetch failed for {vid}: {e}")

    all_cves = sorted({a for d in details.values() for a in d.get("aliases", []) + [d.get("id", "")]
                       if a.startswith("CVE-")})
    kev = _load_kev(warnings) if all_cves else {}
    epss = _load_epss(all_cves, warnings)

    # OSV often lists the same CVE under several advisory IDs (e.g. GHSA-… and PYSEC-…).
    # Collapse them to one entry per (package, CVE), keeping the highest severity.
    sev_rank = {"critical": 0, "high": 1, "medium": 2}
    best: dict[tuple, tuple] = {}
    for dep, ids in per_dep:
        for vid in ids:
            v = details.get(vid, {"id": vid})
            cves = [a for a in v.get("aliases", []) + [v.get("id", "")] if a.startswith("CVE-")]
            key = (dep["name"], dep["version"], cves[0] if cves else vid)
            ghsa_sev = ((v.get("database_specific", {}) or {}).get("severity", "") or "").upper()
            prelim = "high" if ghsa_sev in ("CRITICAL", "HIGH") else "medium"
            fixed = _fixed_versions(v)
            if key not in best:
                best[key] = (dep, vid, v, fixed, prelim)
            else:
                b_dep, b_vid, b_v, b_fixed, b_sev = best[key]
                merged = b_fixed + [f for f in fixed if f not in b_fixed]
                if sev_rank[prelim] < sev_rank[b_sev]:
                    best[key] = (dep, vid, v, merged, prelim)
                else:
                    best[key] = (b_dep, b_vid, b_v, merged, b_sev)

    findings, rows = [], []
    for dep, vid, v, merged_fixed, _ in best.values():
        cves = [a for a in v.get("aliases", []) + [v.get("id", "")] if a.startswith("CVE-")]
        cve = cves[0] if cves else None
        in_kev = bool(cve and cve in kev)
        score = epss.get(cve, 0.0) if cve else 0.0
        ghsa_sev = (v.get("database_specific", {}) or {}).get("severity", "")
        if in_kev:
            sev, controls = "critical", ["AL-10", "AL-11"]
        elif score >= EPSS_CRITICAL:
            sev, controls = "critical", ["AL-11"]
        elif ghsa_sev.upper() in ("CRITICAL", "HIGH"):
            sev, controls = "high", ["AL-11"]
        else:
            sev, controls = "medium", ["AL-11"]
        fixed = merged_fixed
        why = []
        if in_kev:
            k = kev[cve]
            why.append(f"**In CISA KEV** (added {k.get('dateAdded')}; ransomware use: {k.get('knownRansomwareCampaignUse', 'Unknown')})")
        if cve:
            why.append(f"EPSS {score:.2%}")
        if ghsa_sev:
            why.append(f"advisory severity {ghsa_sev}")
        rows.append({
            "package": f"{dep['name']}@{dep['version']}", "ecosystem": dep["ecosystem"],
            "vuln": cve or vid, "kev": in_kev, "epss": round(score, 4),
            "severity": sev, "fixed": fixed[:3], "file": dep["file"],
        })
        findings.append(Finding(
            title=f"{dep['name']}@{dep['version']} vulnerable to {cve or vid}",
            severity=sev,
            source="dependency",
            control_ids=controls,
            file=dep["file"],
            line=dep.get("line"),
            detail=(v.get("summary") or "Known vulnerability.")[:300] + (" — " + "; ".join(why) if why else ""),
            fix=f"Upgrade to {', '.join(fixed[:3])}." if fixed else "No fixed version listed; replace or mitigate.",
            category="dependency",
        ))
    return findings, rows


def to_json(rows: list[dict]) -> str:
    return json.dumps(rows, indent=2)
