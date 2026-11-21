# AuditLens AI System Card

AuditLens is itself an AI system, so it is documented and reviewed the same way it asks teams to treat theirs: an inventory entry, an impact assessment, risk controls, and AuditLens reviewing its own pull requests (see [Self-review](#self-review)).

*Aligned to ISO/IEC 42001 Annex A and the NIST AI RMF. This is a portfolio project; owner fields reflect that.*

## 1. AI inventory entry (ISO 42001 A.4.2 · NIST AI RMF GOVERN 1.6)

| Field | Value |
|---|---|
| System name | AuditLens |
| Owner | Repository maintainer (haneesha33) |
| Purpose | Assist, not replace, human security and compliance review of code changes |
| Deployment | GitHub Action running on pull requests in repositories that opt in |
| Model provider | Anthropic (Claude), via the Messages API |
| Model | Configurable with the `model` input (default `claude-sonnet-5-5`) |
| AI components | Policy agent, AI governance agent (`auditlens/agents.py`) |
| Non-AI components | Secret scanning, built-in rules, Semgrep, Checkov, OSV + CISA KEV + EPSS, AI-component detection |
| Risk level | Medium: outputs inform and can block merges, but humans decide |

## 2. Impact assessment (ISO 42001 A.5.2–A.5.4 · NIST AI RMF MAP 1.1, MAP 5.1)

**Data sent to the model:** the pull request diff (excluding paths listed in `.auditlens/ignore`), the repository's policy documents, the control catalog, and findings already produced by the deterministic checks.

**Data not intentionally sent:** secrets or personal data. However, if a pull request *contains* a committed secret or personal data, that content is part of the diff. The secret scanner flags such cases; the credential must be rotated regardless.

**Who is affected:** developers whose changes are reviewed; reviewers and approvers who rely on the output; the organization's compliance posture and audit evidence.

**Autonomy:** informational and human-in-the-loop. AuditLens posts a comment and reports a pass/fail check. Whether a failing check blocks merging is a choice the repository owner makes in branch rules, and admins can be granted a documented bypass.

| Potential harm | Likelihood | Mitigation in place |
|---|---|---|
| **False negative**: a real issue is missed | Medium | Deterministic checks run independently of the LLM; the LLM adds coverage but is never the only control |
| **False positive / hallucinated finding** | Medium | Schema-enforced output; every LLM finding must quote a policy sentence; validator drops unknown control IDs and files outside the change; 🤖 label on every AI-generated item |
| **Prompt injection via code under review** (e.g. a comment telling the model to approve) | Medium | LLM output can only *add* findings; it cannot remove or downgrade deterministic findings, and it is validated structured data that is never executed |
| **Overstated assurance in evidence** | Low | Evidence uses *fail / no findings / not applicable / performed*; "no findings" is explicitly not reported as "pass" |
| **Sensitive code shared with a third-party model** | Low–Medium | Opt-in per repository; paths can be excluded only with a recorded reason, approver and expiry (max 90 days); the provider must go through the organization's vendor review (see §3) |
| **Cost or availability issues** | Low | `max_tokens` set on every call; 120 s timeout; agents are skipped, not retried in a loop, if the API fails |

**Residual risk:** acceptable for an assistive review tool, provided the owner reviews AI-generated findings before acting and keeps deterministic checks enabled.

## 3. Third parties (ISO 42001 A.10.3 · NIST AI RMF GOVERN 6.1)

The only AI provider is Anthropic. Before using AuditLens on proprietary code, an organization should run its standard vendor review: data handling and retention terms for API use, whether API data is used for training, and contractual commitments. This project does not make claims about those terms; check the provider's current documentation and agreements.

## 4. Operation and monitoring (ISO 42001 A.6.2.6, A.6.2.8 · NIST AI RMF MANAGE 4.1)

- Every run writes a JSON **evidence record** (checks run, findings, control statuses, exclusions, warnings) uploaded as a workflow artifact.
- GitHub Actions logs record each run; agent failures are written to the report's *Run notes* instead of failing silently.
- The readiness dashboard aggregates evidence across pull requests.

## 5. Verification and validation (ISO 42001 A.6.2.4 · NIST AI RMF MEASURE 2.7)

- Validated against a demo repository with three intentionally vulnerable pull requests (AI chatbot, vulnerable dependencies, cloud infrastructure).
- Output was reviewed manually after each change; issues found this way were fixed (de-duplication, path mapping, severity defaults, evidence status semantics).
- **Known limitations:** heuristic AI-security rules can produce false positives and negatives; only the diff is reviewed, not the whole system; the control mapping is a curated subset and should be verified against the licensed standards.

## 6. Self-review

AuditLens runs on its own pull requests through `.github/workflows/self-review.yml`. Paths that contain detection patterns or deliberately insecure demo content are excluded in [`.auditlens/ignore`](.auditlens/ignore). Each exclusion needs a written reason, a named approver and an expiry date no more than 90 days away; incomplete or expired entries are not applied, so those files are scanned again until the exception is renewed. This rule came from AuditLens's own review of the PR that introduced the exclusions. The exclusions appear in the review comment and in the evidence record, so they stay visible and auditable.

## 7. Review

| Item | Value |
|---|---|
| Last reviewed | November 2026 |
| Next review | On any change to agents, prompts, model, or data sent to the model |
