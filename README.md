# Okta Audit via API Token Guide

## Overview
- This guide outlines API checks for auditing Okta configurations using a dedicated API token
- `okta-audit.sh` attempts to automate all of these checks in one script
- Thanks to https://developer.okta.com/ for creating an easy developer experience

## Prerequisites

Before beginning, configure your environment:

```bash
export OKTA_API_TOKEN="<Your-Okta-API-Token>"
export OKTA_DOMAIN="<Your-Org>.okta.com"  # Or .okta.gov for Gov/FedRAMP
```

Ensure `jq` is installed:
- macOS: `brew install jq`
- Debian/Ubuntu: `sudo apt-get install jq`

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

Review the JSON output for:
- Allowed authenticators (e.g., FIDO2, Okta Verify)
- Verification that non-compliant methods are disabled

### 2. Management Console Login Security

Check sign-on policies for admin console MFA:
```bash
curl -s -X GET \
  -H "Authorization: SSWS ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
| jq
```

Verify policies enforcing MFA for administrator groups.

### 3. FIPS Compliance

Verification points:
- Confirm FedRAMP package type
- Verify domain is `.okta.mil` or `.okta.gov`
- Test accessibility of `support.okta-gov.com`

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

### 12. Behavioral Detection

Configuration is primarily done through Admin UI:
- Security → Behavior Detection
- Limited API visibility through MFA_ENROLL and OKTA_SIGN_ON policies

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