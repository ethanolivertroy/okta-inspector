# Okta FedRAMP Compliance Audit Tool

<img src="image.webp" width="600" alt="Okta Audit">


## Overview
- A comprehensive tool for evaluating Okta configurations for FedRAMP compliance
- Aligns with NIST 800-53 controls for identity and access management
- Validates FIPS 140-2/140-3 cryptographic compliance for federal systems
- `okta-audit.sh` automates all checks and generates a compliance summary report
- Built to support U.S. Federal security requirements and guidelines
- Thanks to https://developer.okta.com/ for their comprehensive API documentation

## NIST Controls Coverage
This tool evaluates Okta configurations against these key NIST 800-53 controls:
- **AC-2**: Account Management
- **AC-3**: Access Enforcement
- **AC-7**: Unsuccessful Login Attempts
- **AC-11**: Session Lock
- **IA-2**: Identification and Authentication
- **IA-5**: Authenticator Management
- **IA-8**: Identification and Authentication (Non-organizational Users)
- **AU-2**: Audit Events
- **SI-4**: Information System Monitoring

## Prerequisites

Before beginning, ensure these tools are installed:

- `bash` (version 4 or later)
- `jq` for JSON processing:
  - macOS: `brew install jq`
  - Debian/Ubuntu: `sudo apt-get install jq`
  - RHEL/CentOS: `sudo yum install jq`
- `curl` for API requests
- `zip` for creating archives of results

## Getting Started

### Using the Automated Script

The `okta-audit.sh` script automates all the compliance checks in one run:

1. Make the script executable:
   ```bash
   chmod +x okta-audit.sh
   ```

2. Run the script using one of these methods:

   **Interactive mode** (will prompt for credentials):
   ```bash
   ./okta-audit.sh
   ```

   **Command-line arguments**:
   ```bash
   ./okta-audit.sh --domain your-org.okta.com --token YOUR_API_TOKEN
   ```

   **Environment variables**:
   ```bash
   export OKTA_API_TOKEN="YOUR_API_TOKEN"
   export OKTA_DOMAIN="your-org.okta.com"
   ./okta-audit.sh --non-interactive
   ```

### Script Options

```
Usage: ./okta-audit.sh [options]

Options:
  -d, --domain DOMAIN       Your Okta domain (e.g., your-org.okta.com)
  -t, --token TOKEN         Your Okta API token
  -o, --output-dir DIR      Custom output directory (default: timestamped dir)
  -i, --interactive         Force interactive mode even if arguments provided
  -n, --non-interactive     Use non-interactive mode with provided arguments
  -p, --page-size SIZE      Number of items per page for API calls (default: 200)
  -h, --help                Show this help message and exit
  --oauth                   Use OAuth 2.0 token instead of SSWS token
```

### Understanding Results

After running, the script creates a timestamped directory with:
- JSON files containing raw data from each API call
- A FedRAMP compliance summary report
- FIPS compliance assessment
- A ZIP archive of all results

Example output:
```
All checks complete!
Results directory: okta_audit_results_20250409_170434
Zipped archive:    okta_audit_20250409.zip
FedRAMP summary:   okta_audit_results_20250409_170434/fedramp_compliance_summary.md
FIPS compliance:   okta_audit_results_20250409_170434/fips_compliance_report.txt
```

### Obtaining an Okta API Token

1. Log in to your Okta Admin Console
2. Navigate to **Security → API**
3. Select **Tokens** tab and click **Create Token**
4. Give your token a meaningful name and copy the generated value
5. Use this token with the `--token` option or `OKTA_API_TOKEN` environment variable

## Audit Checklist

### 1. Authentication Types & Phishing-Resistant MFA

List MFA enrollment policies:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" \
| jq
```

Check FIDO2 Auth Policy settings:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=ACCESS_POLICY" \
| jq
```

Get FIDO2 authenticator configuration:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/authenticators" \
| jq
```

Review the JSON output for:
- Allowed authenticators (e.g., FIDO2, Okta Verify)
- Verification that non-compliant methods are disabled
- FIDO2 WebAuthn configuration and requirements

### 2. Management Console Login Security

Check sign-on policies for admin console MFA:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
| jq
```

Get current session information and lifetime:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/sessions/me" \
| jq
```

Check global session settings in authorization servers:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/authorizationServers" \
| jq
```

Verify policies enforcing MFA for administrator groups and review session lifetime configuration.

### 3. FIPS Compliance

Verification points:
- Confirm FedRAMP package type
- Verify domain is `.okta.mil` or `.okta.gov`
- Test accessibility of `support.okta-gov.com`
- Check FIPS-validated cryptographic modules

Check FIPS encryption compliance:
```bash
# Check TLS and cryptographic settings
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/authorizationServers/default" \
| jq

# Check FIPS mode through Factors API
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/org/factors" \
| jq '.[] | select(.provider.type == "FIDO" or .provider.type == "RSA" or .provider.type == "SYMANTEC")'

# Check IdP settings for FIPS-compliant SHA-256 algorithms
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/idps" \
| jq '.[] | select(.protocol.algorithms.request.signature.algorithm == "SHA-256" or .protocol.algorithms.response.signature.algorithm == "SHA-256")'

# Check system log for FIPS-related crypto events
SINCE=$(date -u -d '30 days ago' +"%Y-%m-%dT%H:%M:%SZ")
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&filter=eventType+eq+\"system.crypto.operations\"&limit=100" \
| jq
```

Review for:
- TLS 1.2 or higher with FIPS-approved cipher suites
- FIPS 140-2/140-3 validated cryptographic modules
- FIPS-compliant factors (RSA/Symantec tokens, FIPS-certified hardware keys)
- Use of SHA-256 or stronger signature algorithms
- Any system logs indicating use of FIPS cryptographic providers

### 4. Integration Validation

List active applications:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/apps?limit=200" \
| jq
```

Compare against your documented application inventory.

### 5. Global Access and Session Controls

Review sign-on policies for:
- MFA requirements
- Session timeouts
- Session cookie configurations

```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
| jq
```

### 6. Admin Role Review

Check roles for specific users:
```bash
USER_ID="<Okta-User-ID-or-Login>"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users/${USER_ID}/roles" \
| jq
```

Search for admin users:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?search=profile.userType+eq+\"ADMIN\"" \
| jq
```

### 7. Admin Group Assignments

List all groups:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/groups?limit=200" \
| jq
```

View group members:
```bash
GROUP_ID="<Group-ID>"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/groups/${GROUP_ID}/users" \
| jq
```

### 8. User Status Review

List users by status:
```bash
STATUS="ACTIVE"  # Options: LOCKED_OUT, PASSWORD_EXPIRED, RECOVERY, SUSPENDED, DEPROVISIONED
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?limit=200&filter=status+eq+\"${STATUS}\"" \
| jq
```

#### Find Inactive Users

Method 1: Using search parameter with last login date (preferred method):
```bash
# Format date in ISO 8601 format with milliseconds
NINETY_DAYS_AGO=$(date -u -d '90 days ago' +"%Y-%m-%dT%H:%M:%S.000Z")
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?search=last_login%20lt%20%22${NINETY_DAYS_AGO}%22&limit=200" \
| jq > inactive_users_by_login.json
```

Method 2: Get users with inactive statuses:
```bash
for STATUS in SUSPENDED DEPROVISIONED LOCKED_OUT PASSWORD_EXPIRED; do
  curl -s -X GET \
    -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
    -H "Accept: application/json" \
    "https://${OKTA_DOMAIN}/api/v1/users?filter=status%20eq%20%22${STATUS}%22&limit=200" \
    | jq > "inactive_${STATUS}.json"
done
```

Method 3: Filter locally using jq (if API filtering is unavailable):
```bash
# Get all active users
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?filter=status+eq+\"ACTIVE\"&limit=200" \
| jq > active_users.json

# Filter locally for lastLogin older than 90 days
NINETY_DAYS_AGO=$(date -u -d '90 days ago' +"%Y-%m-%dT%H:%M:%S.000Z")
jq --arg date "${NINETY_DAYS_AGO}" '[.[] | select(.lastLogin != null and .lastLogin < $date)]' \
  active_users.json > inactive_by_jq_filter.json
```

### 9. Password Policy Review

Check password policies:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
| jq
```

Review:
- Target groups
- Minimum requirements
- First login password change rules

### 10. Reporting Capabilities

Use System Log API for:
- YubiKey usage
- MFA enrollment statistics
- Custom reporting needs

### 11. SIEM Integration

Pull system logs:
```bash
SINCE="2025-01-01T00:00:00Z"
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000" \
| jq
```

Note: Handle pagination using the `Link` header with `rel="next"`.

### 12. Behavioral Detection and Threat Insight Settings

Configuration is primarily done through Admin UI:
- Security → Behavior Detection
- Limited API visibility through MFA_ENROLL and OKTA_SIGN_ON policies

Check Threat Insight settings and exempt network zones:
```bash
# Get Threat Insight configuration (including exempt zones)
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/threats/configuration" \
| jq

# Get all Network Zones for cross-reference
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/zones" \
| jq
```

Review which network zones (if any) are exempted from Threat Insight detection.

### 13. Notification Settings

Check email templates:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/templates/email" \
| jq
```

Primary configuration in Admin UI:
- Security → General → Security → Notification Emails

### 14. API Token Management

Note: API token management is restricted to the Admin Console UI. No direct API endpoint exists for listing SSWS tokens.

### 15. Federal Subscription Validation

Manual verification required:
- Domain check (.okta.gov or .okta.mil)
- FedRAMP compliance documentation review

## Saving Outpus and Filtering Data

### Save Outputs
```bash
# Save to file
curl -s ... | jq '.' > policies.json

# Save and display
curl -s ... | jq '.' | tee password_policies.json
```

### Filter Data
```bash
# Extract specific fields
curl -s ... | jq '.[] | {id, name, conditions, status}'
```