"""Git diff helpers: changed files, added lines and the raw unified diff."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def changed_files(repo: Path, base: str, head: str) -> list[str]:
    out = _git(repo, "diff", "--name-only", "--diff-filter=ACMR", f"{base}...{head}")
    return [line.strip() for line in out.splitlines() if line.strip()]


def added_lines(repo: Path, base: str, head: str) -> dict[str, list[tuple[int, str]]]:
    """Return {file: [(line_number_in_new_file, text), ...]} for every added line."""
    out = _git(repo, "diff", "-U0", "--diff-filter=ACMR", f"{base}...{head}")
    result: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    lineno = 0
    for raw in out.splitlines():
        if raw.startswith("+++ "):
            path = raw[4:]
            current = path[2:] if path.startswith("b/") else None
            if current:
                result.setdefault(current, [])
            continue
        m = HUNK_RE.match(raw)
        if m:
            lineno = int(m.group(1))
            continue
        if current is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            result[current].append((lineno, raw[1:]))
            lineno += 1
        elif raw.startswith(" "):
            lineno += 1
    return result


def unified_diff(repo: Path, base: str, head: str, max_chars: int = 60000) -> str:
    out = _git(repo, "diff", "-U3", "--diff-filter=ACMR", f"{base}...{head}")
    if len(out) > max_chars:
        out = out[:max_chars] + "\n\n[... diff truncated for length ...]\n"
    return out


def head_sha(repo: Path, head: str) -> str:
    return _git(repo, "rev-parse", head).strip()


def read_file(repo: Path, rel: str) -> str:
    p = repo / rel
    try:
        return p.read_text(errors="ignore")
    except OSError:
        return ""
