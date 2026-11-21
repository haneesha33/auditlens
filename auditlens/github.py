"""Post or update the AuditLens comment on a pull request."""
from __future__ import annotations

import json
import os

from .http import request_json
from .report import MARKER

API = "https://api.github.com"


def pr_number_from_event() -> int | None:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path or not os.path.exists(path):
        return None
    with open(path) as fh:
        event = json.load(fh)
    return (event.get("pull_request") or {}).get("number")


def upsert_comment(repo: str, pr: int, body: str, token: str) -> str:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    comments = request_json(f"{API}/repos/{repo}/issues/{pr}/comments?per_page=100", headers=headers)
    for c in comments:
        if MARKER in (c.get("body") or ""):
            request_json(f"{API}/repos/{repo}/issues/comments/{c['id']}", method="PATCH",
                         body={"body": body}, headers=headers)
            return "updated"
    request_json(f"{API}/repos/{repo}/issues/{pr}/comments", method="POST", body={"body": body}, headers=headers)
    return "created"
