"""Deterministic AI security checks + AI system detection.

These run without an LLM, so the core findings are reproducible and explainable.
The AI governance agent adds context on top of them.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb"}

# ---------- AI system detection ----------
PROVIDERS = {
    "OpenAI": [r"\bimport openai\b", r"\bfrom openai\b", r"['\"]openai['\"]", r"api\.openai\.com"],
    "Anthropic": [r"\bimport anthropic\b", r"\bfrom anthropic\b", r"@anthropic-ai/sdk", r"api\.anthropic\.com"],
    "Google Gemini": [r"google\.generativeai", r"google\.genai", r"@google/generative-ai"],
    "AWS Bedrock": [r"bedrock-runtime", r"\bBedrock\w*\("],
    "Azure OpenAI": [r"AzureOpenAI", r"openai\.azure\.com"],
    "Cohere": [r"\bimport cohere\b", r"\bfrom cohere\b"],
    "Mistral": [r"\bmistralai\b"],
    "Hugging Face": [r"\bfrom transformers\b", r"\bimport transformers\b", r"huggingface_hub"],
    "LangChain": [r"\blangchain\b"],
    "LlamaIndex": [r"\bllama_index\b"],
}
VECTOR_STORES = {
    "Pinecone": r"\bpinecone\b", "Chroma": r"\bchromadb\b", "Weaviate": r"\bweaviate\b",
    "Qdrant": r"\bqdrant", "FAISS": r"\bfaiss\b", "pgvector": r"pgvector", "Milvus": r"pymilvus",
}
MODEL_RE = re.compile(r"""model(?:_id|Id|_name)?\s*[=:]\s*["']([A-Za-z0-9_.:/\-]{3,80})["']""")
LLM_CALL_RE = re.compile(
    r"(messages\.create|chat\.completions\.create|responses\.create|generate_content|invoke_model|\.invoke\(|completions\.create)"
)

# ---------- Secrets (work even when Semgrep isn't installed) ----------
SECRET_PATTERNS = [
    ("Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
    ("OpenAI API key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}"),
    ("AWS access key ID", r"\bAKIA[0-9A-Z]{16}\b"),
    ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ("Slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    ("Private key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("Hardcoded credential", r"""(?i)\b(api_?key|secret|password|passwd|token|auth_token)\b\s*[:=]\s*["'][^"'\s]{8,}["']"""),
]
SAFE_SECRET_HINTS = ("getenv", "environ", "process.env", "secrets.", "os.environ", "<", "example", "changeme", "xxxx")

# ---------- AI risk heuristics ----------
USER_INPUT = r"(request\.|req\.body|req\.query|user_input|user_message|userInput|params\[|input\(|query|question|message\b|form\[|body\[|email_body|document|web_content)"
PROMPT_CTX = r"(prompt|system|instruction|messages|role|content)"
FSTRING = r"""(\bf["']|\.format\(|\$\{|["']\s*\+\s*\w|\w\s*\+\s*["'])"""
PII = r"(\bemail\b|\bssn\b|social_security|date_of_birth|\bdob\b|phone|address|customer\.|patient|credit_card|card_number|full_name)"
LLM_OUTPUT = r"(response|completion|output|result|answer|choices\[|\.content|\.text|generated|llm_)"
DANGEROUS_SINK = r"(\beval\(|\bexec\(|subprocess\.|os\.system\(|os\.popen\(|\.execute\(\s*f?[\"']?|innerHTML|dangerouslySetInnerHTML|\|\s*safe\b|Markup\()"
DANGEROUS_TOOL = r"(run_shell|shell|execute_command|exec_code|run_code|delete_\w+|drop_table|transfer_funds|send_email|send_payment|rm -rf|subprocess)"
TOOL_CTX = r"(\btools?\b|function|@tool|\"name\"\s*:|'name'\s*:|tool_choice|Tool\()"
SYSPROMPT_SECRET = r"(?i)(system|prompt).*(password|api[_ ]?key|secret|credential|internal only|do not reveal)"


def _is_code(path: str) -> bool:
    return Path(path).suffix in CODE_EXT


def detect_ai_systems(repo: Path, files: list[str]) -> list[dict]:
    """Inspect full content of changed code files to identify AI components."""
    inventory = []
    for f in files:
        if not _is_code(f):
            continue
        p = repo / f
        if not p.exists():
            continue
        text = p.read_text(errors="ignore")
        providers = [name for name, pats in PROVIDERS.items() if any(re.search(x, text) for x in pats)]
        stores = [name for name, pat in VECTOR_STORES.items() if re.search(pat, text)]
        if providers or stores:
            models = sorted(set(MODEL_RE.findall(text)))
            inventory.append({
                "file": f,
                "providers": providers,
                "vector_stores": stores,
                "models": models[:5],
                "makes_llm_calls": bool(LLM_CALL_RE.search(text)),
                "has_logging": bool(re.search(r"(logger|logging\.|log\.|audit)", text)),
                "has_token_limit": bool(re.search(r"(max_tokens|max_output_tokens|max_completion_tokens|maxTokens)", text)),
            })
    return inventory


def scan_secrets(added: dict[str, list[tuple[int, str]]]) -> list[Finding]:
    findings = []
    for path, lines in added.items():
        if path.endswith((".md", ".lock")):
            continue
        for ln, text in lines:
            low = text.lower()
            for label, pat in SECRET_PATTERNS:
                if re.search(pat, text) and not any(h in low for h in SAFE_SECRET_HINTS):
                    findings.append(Finding(
                        title=f"{label} committed to source code",
                        severity="critical",
                        source="secrets",
                        control_ids=["AL-01"],
                        file=path, line=ln,
                        detail="A secret value appears in an added line. Anyone with repo access (and git history) can use it.",
                        fix="Remove it, rotate the credential now, and load it from the secrets manager via an environment variable.",
                    ))
                    break
    return findings


def scan_ai_risks(added: dict[str, list[tuple[int, str]]], inventory: list[dict]) -> list[Finding]:
    ai_files = {i["file"]: i for i in inventory}
    findings: list[Finding] = []

    def add(path, ln, title, sev, controls, detail, fix):
        findings.append(Finding(title=title, severity=sev, source="ai-check", control_ids=controls,
                                file=path, line=ln, detail=detail, fix=fix, category="ai-security"))

    for path, lines in added.items():
        if path not in ai_files:
            continue
        for ln, text in lines:
            if re.search(DANGEROUS_SINK, text) and re.search(LLM_OUTPUT, text, re.I):
                add(path, ln, "Model output flows into a dangerous sink (code/command/SQL/HTML)", "critical",
                    ["AL-24", "AL-07"],
                    "LLM output is attacker-influenced (via prompt injection) and must be treated as untrusted input.",
                    "Parse output into a strict schema, allow-list actions, and never eval/exec or concatenate it into SQL/shell/HTML.")
            elif re.search(FSTRING, text) and re.search(USER_INPUT, text, re.I) and re.search(PROMPT_CTX, text, re.I):
                add(path, ln, "Untrusted input interpolated directly into prompt", "high", ["AL-22"],
                    "User-controlled text is mixed into the instruction string, so it can override instructions (prompt injection).",
                    "Keep system instructions static; pass user input as a separate user message, delimit it, and validate it.")
            if re.search(PII, text, re.I) and (re.search(PROMPT_CTX, text, re.I) or re.search(FSTRING, text)):
                add(path, ln, "Personal data appears to be sent to an AI model", "high", ["AL-23", "AL-06"],
                    "PII in prompts leaves your boundary and goes to the model provider.",
                    "Minimize or redact PII before the call, confirm the provider is approved with a no-training DPA, and record it in the impact assessment.")
            if re.search(DANGEROUS_TOOL, text, re.I) and re.search(TOOL_CTX, text, re.I):
                add(path, ln, "AI agent given a high-impact tool", "high", ["AL-25"],
                    "Tools that run code, delete data, send messages or move money give a prompt-injected model real-world impact.",
                    "Scope the tool narrowly and require human approval before execution.")
            if re.search(SYSPROMPT_SECRET, text):
                add(path, ln, "System prompt contains sensitive content", "medium", ["AL-28"],
                    "System prompts can be extracted by users; treat them as public.",
                    "Move secrets and sensitive logic out of the prompt into server-side code.")

        info = ai_files[path]
        # Point at the model call itself when it's in the diff, otherwise the first added line.
        call_lines = [ln for ln, text in lines if LLM_CALL_RE.search(text)]
        first_line = call_lines[0] if call_lines else (lines[0][0] if lines else None)
        if info["makes_llm_calls"] and not info["has_token_limit"]:
            add(path, first_line, "LLM call without a token limit", "medium", ["AL-26"],
                "Unbounded generation risks cost blowups and denial of wallet.",
                "Set max_tokens and a timeout on every model call; rate-limit user-facing features.")
        if info["makes_llm_calls"] and not info["has_logging"]:
            add(path, first_line, "AI interactions are not logged", "low", ["AL-27"],
                "Without logs there is no monitoring or audit trail for AI behaviour (ISO 42001 A.6.2.8).",
                "Log prompts, outputs, model version and tool calls with PII redacted.")
    return findings


def governance_actions(inventory: list[dict]) -> list[Finding]:
    """Paperwork the change triggers: inventory, impact assessment, vendor review."""
    if not inventory:
        return []
    providers = sorted({p for i in inventory for p in i["providers"] + i["vector_stores"]})
    files = ", ".join(i["file"] for i in inventory)
    out = [
        Finding(title="Register AI system in the AI inventory", severity="medium", source="ai-check",
                control_ids=["AL-20"], file=inventory[0]["file"], category="governance",
                detail=f"AI components detected in: {files}.",
                fix="Add the draft inventory entry below to the AI inventory with an owner and risk level."),
        Finding(title="Complete an AI impact assessment", severity="medium", source="ai-check",
                control_ids=["AL-21"], file=inventory[0]["file"], category="governance",
                detail="New or changed AI functionality requires an impact assessment before production.",
                fix="Review and finalize the draft impact assessment generated below."),
    ]
    if providers:
        out.append(Finding(title=f"Confirm vendor approval for: {', '.join(providers)}", severity="medium",
                           source="ai-check", control_ids=["AL-13"], file=inventory[0]["file"], category="governance",
                           detail="AI providers and hosted vector stores receive company data and need vendor review.",
                           fix="Check the approved vendor list; if missing, open a vendor security review and confirm a no-training DPA."))
    return out
