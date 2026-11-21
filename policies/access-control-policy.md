# Access Control Policy (Sample)

*Fictional sample policy for the AuditLens demo. Not any real company's policy.*

## 1. Purpose
Ensure access to systems and data is limited to authorized users, services and processes.

## 2. Scope
All production systems, cloud accounts, source code repositories and service accounts.

## 3. Requirements

### 3.1 Identity
All human access uses SSO with MFA. Shared accounts are prohibited.

### 3.2 Least privilege
IAM roles, service accounts and API tokens are granted the minimum permissions needed. Wildcard permissions (`*` actions or resources) are prohibited in production without a documented exception.

### 3.3 Access reviews
Privileged access is reviewed quarterly.

### 3.4 Secrets management
Secrets (API keys, passwords, tokens, private keys, connection strings) must never be committed to source code, configuration files or container images. Secrets are stored in the approved secrets manager and injected at runtime through environment variables or secret mounts.

## 4. Exceptions
Exceptions require written approval from the Security team and expire after 90 days.
