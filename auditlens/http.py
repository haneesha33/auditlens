"""Tiny stdlib HTTP helper (keeps dependencies minimal)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

USER_AGENT = "AuditLens/0.1 (+https://github.com)"


def request_json(url: str, method: str = "GET", body: dict | None = None,
                 headers: dict | None = None, timeout: int = 30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="ignore")[:500]
        raise RuntimeError(f"HTTP {e.code} from {url}: {detail}") from e
