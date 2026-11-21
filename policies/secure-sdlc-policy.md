# Secure Software Development Lifecycle Policy (Sample)

*Fictional sample policy for the AuditLens demo. Not any real company's policy.*

## 1. Purpose
Build security into software from design through deployment.

## 4. Development requirements

### 4.1 Code review
Every change to production code is peer reviewed and passes automated security checks before merge.

### 4.2 Authentication and authorization
Every new API endpoint enforces authentication and checks authorization for the requested resource. Unauthenticated endpoints require Security approval.

### 4.4 Secure coding
Code must not build SQL queries, shell commands or HTML through string concatenation with untrusted input. `eval`, `exec` and dynamic code execution on untrusted data are prohibited.

### 4.6 Logging
Authentication events, authorization failures and administrative actions are logged. Logs must not contain secrets or personal data.

## 5. Infrastructure

### 5.1 Hardened baseline
Infrastructure as code (Terraform, CloudFormation, Kubernetes manifests) must follow the hardened baseline: encryption enabled, logging enabled, no public exposure unless approved.

## 6. Vulnerability management

### 6.1 Known exploited vulnerabilities
Dependencies with vulnerabilities in the CISA Known Exploited Vulnerabilities (KEV) catalog must not be merged.

### 6.2 Remediation SLAs
Critical: 7 days. High: 30 days. Medium: 90 days. Vulnerabilities with EPSS ≥ 0.10 are treated as Critical.
