# AI Acceptable Use and Development Policy (Sample)

*Fictional sample policy for the AuditLens demo, aligned to ISO/IEC 42001 and NIST AI RMF. Not any real company's policy.*

## 1. Purpose
Ensure AI systems are developed and used responsibly, securely and transparently.

## 2. Governance

### 2.1 AI inventory
Every AI system (any feature that calls a machine learning model or LLM, internal or third party) is registered in the AI inventory with owner, purpose, model provider, data used and risk level before production.

### 2.3 Impact assessment
New AI features, or material changes to existing ones, require an AI impact assessment covering affected individuals, potential harms, data used and mitigations.

## 3. Data

### 3.2 Data sent to models
Confidential or Restricted data (including PII) must not be sent to external AI models unless the provider is approved (Vendor Management Policy §2.1), the data is minimized, and the use is recorded in the impact assessment.

## 4. Secure AI development

### 4.1 Prompt injection
Untrusted input (user messages, retrieved documents, web content, emails) must be clearly separated from system instructions and must never be able to change the system's role or tools.

### 4.2 Output handling
Model output is untrusted. It must not be passed to `eval`, `exec`, shell commands, SQL queries or rendered as raw HTML without validation.

### 4.3 Agents and tools
AI agents get only the tools they need. Tools that delete data, move money, send external messages or run code require human approval.

### 4.4 Resource limits
Every model call sets a maximum token limit and timeout; user-facing AI features are rate limited.

### 4.5 System prompts
System prompts must not contain secrets, credentials or information that would be harmful if disclosed.

### 4.6 Retrieval
Retrieval-augmented systems must enforce the requesting user's access rights on retrieved documents.

## 5. Monitoring

### 5.1 Logging
AI interactions (inputs, outputs, model version, tool calls) are logged with PII redacted, and monitored for misuse.

## 6. Transparency

### 6.1 Disclosure
Users are told when they are interacting with AI, and AI-generated content that informs decisions is labeled.
