# Data Classification and Handling Policy (Sample)

*Fictional sample policy for the AuditLens demo. Not any real company's policy.*

## 3. Classification levels
- **Public** — approved for public release.
- **Internal** — business data not for public release.
- **Confidential** — customer data, personal data (PII), credentials, financial data.
- **Restricted** — government IDs, payment card data, health data.

## 4. Handling

### 4.1 Minimization
Collect and process only the data needed for the stated purpose.

### 4.2 Personal data
PII (names, emails, phone numbers, addresses, dates of birth, government IDs) must not be written to logs, analytics or third-party services unless approved and documented in the data inventory.

## 5. Protection

### 5.1 Encryption
Confidential and Restricted data is encrypted at rest (AES-256 or provider-managed keys) and in transit (TLS 1.2+).

### 5.3 Exposure
Storage buckets, databases and file shares holding Internal data or above must not be publicly accessible.
