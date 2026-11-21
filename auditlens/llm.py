"""Minimal Anthropic Messages API client that returns structured JSON via a tool schema.

First it asks the model to answer by calling one tool (forced tool use), so the output
always matches `schema`. Some models don't support forcing a tool; in that case it
retries with tool_choice "auto" plus an instruction to call the tool, and as a last
resort parses JSON out of a plain-text answer.
"""
from __future__ import annotations

import json
import os
import re

from .http import request_json

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-5-5"


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _post(body: dict) -> dict:
    return request_json(API_URL, method="POST", body=body, timeout=120, headers={
        "x-api-key": os.environ["ANTHROPIC_API_KEY"],
        "anthropic-version": "2023-06-01",
    })


def _extract(resp: dict, tool_name: str) -> dict | None:
    content = resp.get("content", [])
    for block in content:
        if block.get("type") == "tool_use" and block.get("name") == tool_name:
            return block.get("input", {})
    text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
    match = re.search(r"\{.*\}", text, re.S)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
    return None


def structured_call(system: str, user: str, tool_name: str, tool_description: str,
                    schema: dict, max_tokens: int = 4000) -> dict:
    body = {
        "model": os.environ.get("AUDITLENS_MODEL") or DEFAULT_MODEL,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user}],
        "tools": [{"name": tool_name, "description": tool_description, "input_schema": schema}],
        "tool_choice": {"type": "tool", "name": tool_name},
    }
    try:
        resp = _post(body)
    except RuntimeError as e:
        if "tool_choice" not in str(e):
            raise
        # Model doesn't support forced tool use: ask for it in words instead.
        body["tool_choice"] = {"type": "auto"}
        body["system"] = (system + f"\n\nAlways respond by calling the `{tool_name}` tool exactly once "
                          "with your complete answer. Do not reply with plain text.")
        resp = _post(body)

    result = _extract(resp, tool_name)
    if result is None:
        raise RuntimeError("Model did not return structured output.")
    return result
