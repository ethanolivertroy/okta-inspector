#!/usr/bin/env bash
#
# okta_audit.sh
#
# A comprehensive script to retrieve Okta configuration and logs for FedRAMP assessment.
# Performs checks aligned with NIST 800-53 controls for identity and access management.
# 
# Controls assessed include:
#   - IA-2: Identification and Authentication
#   - IA-5: Authenticator Management
#   - AC-2: Account Management
#   - AC-3: Access Enforcement
#   - AC-7: Unsuccessful Login Attempts
#   - AC-11: Session Lock
#   - AU-2: Audit Events
#   - SI-4: Information System Monitoring
#
# Requires:
#   - Bash 4+ (for associative arrays if needed)
#   - jq (for JSON pretty-printing)
#   - zip
#
# Usage:
#   Run this script:
#     ./okta-audit.sh
#   You will be prompted for your Okta domain and API token.

set -euo pipefail

# Check prerequisites
if ! command -v jq &>/dev/null; then
  echo "ERROR: 'jq' is not installed or not in PATH. Please install it." >&2
  exit 1
fi

if ! command -v zip &>/dev/null; then
  echo "ERROR: 'zip' is not installed or not in PATH. Please install it." >&2
  exit 1
fi

# Prompt for Okta domain and API token
read -p "Enter your Okta domain (e.g., your-org.okta.com or your-org.okta.gov): " OKTA_DOMAIN
read -sp "Enter your Okta API token: " OKTA_API_TOKEN
echo  # Add newline after hidden input

# Validate inputs
if [ -z "${OKTA_DOMAIN}" ] || [ -z "${OKTA_API_TOKEN}" ]; then
  echo "ERROR: Both Okta domain and API token are required."
  exit 1
fi

# Add SSWS prefix if not present
if [[ ! $OKTA_API_TOKEN =~ ^SSWS ]]; then
  OKTA_API_TOKEN="SSWS ${OKTA_API_TOKEN}"
fi

# Create a timestamped output directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="okta_audit_results_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

echo "Running Okta FedRAMP assessment checks..."
echo "Outputs will be saved to: $OUTPUT_DIR"

##############################################
# Helper function for GET calls
##############################################
okta_get() {
  local url="$1"
  local output_file="$2"
  local tmp_response
  local http_code

  # Use a temporary file for the response
  tmp_response=$(mktemp)

  # Make the request, capturing both the body and HTTP code
  http_code=$(curl -s -w "%{http_code}" \
    -X GET \
    -H "Authorization: ${OKTA_API_TOKEN}" \
    -H "Accept: application/json" \
    "${url}" \
    -o "${tmp_response}")

  # Check HTTP response code
  if [ "$http_code" -ne 200 ]; then
    echo "Warning: API request failed with HTTP code ${http_code}" >&2
    echo "[]" > "$output_file"
    rm -f "${tmp_response}"
    return 1
  fi

  # Verify we got valid JSON and write to output file
  if jq '.' "${tmp_response}" > "$output_file" 2>/dev/null; then
    rm -f "${tmp_response}"
    return 0
  else
    echo "Warning: Invalid JSON response received" >&2
    echo "[]" > "$output_file"
    rm -f "${tmp_response}"
    return 1
  fi
}

##############################################
# Test the API connection
##############################################
echo "Testing API connection..."
TEST_FILE=$(mktemp)
if ! okta_get "https://${OKTA_DOMAIN}/api/v1/users?limit=1" "$TEST_FILE"; then
  echo "ERROR: Failed to connect to Okta API. Please verify your domain and API token."
  echo "Make sure:"
  echo "  1. Your domain is correct (${OKTA_DOMAIN})"
  echo "  2. Your API token is valid and has the necessary permissions"
  echo "  3. You included 'SSWS ' if you manually copied the entire token"
  rm -f "$TEST_FILE"
  exit 1
fi
rm -f "$TEST_FILE"
echo "API connection successful!"

##############################################
# 1. Okta Supported Authentication Types (MFA)
##############################################
echo "1) Retrieving MFA Enrollment Policies..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=MFA_ENROLL" \
  "${OUTPUT_DIR}/mfa_enrollment_policies.json"

# Get FIDO2 Auth Policy settings
echo "1a) Retrieving FIDO2 Auth Policy settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=ACCESS_POLICY" \
  "${OUTPUT_DIR}/access_policies.json"

# Get FIDO2 authenticator specific policies
echo "1b) Retrieving FIDO2 authenticator settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/authenticators" \
  "${OUTPUT_DIR}/authenticators.json"

##############################################
# 2. Okta Management Console Login Evaluation
##############################################
echo "2) Retrieving Sign-On Policies..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
  "${OUTPUT_DIR}/sign_on_policies.json"

# Get Session Lifetime settings 
echo "2a) Retrieving Session Lifetime settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/sessions/me" \
  "${OUTPUT_DIR}/session_info.json"

# Get global session settings
echo "2b) Retrieving Global Session Settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/authorizationServers" \
  "${OUTPUT_DIR}/authorization_servers.json"

##############################################
# 3. Okta FIPS Compliance
##############################################
echo "3) Saving FedRAMP domain info..."
tee "${OUTPUT_DIR}/fedramp_domain_info.txt" <<EOF
Domain used: ${OKTA_DOMAIN}
(Verify if .okta.gov or .okta.mil)
Check FedRAMP environment by attempting manual browse to:
https://support.okta-gov.com/help/s/status
EOF

##############################################
# 4. Okta Integration Validations (Apps)
##############################################
echo "4) Retrieving list of active/assigned apps..."
okta_get "https://${OKTA_DOMAIN}/api/v1/apps?limit=200" \
  "${OUTPUT_DIR}/apps.json"

##############################################
# 6. Review Okta Admin Roles
##############################################
echo "6) Retrieving all users (to find Admin roles among them)..."
okta_get "https://${OKTA_DOMAIN}/api/v1/users?limit=200" \
  "${OUTPUT_DIR}/users.json"

##############################################
# 7. Review Okta Admin Group Assignments
##############################################
echo "7) Retrieving all groups..."
okta_get "https://${OKTA_DOMAIN}/api/v1/groups?limit=200" \
  "${OUTPUT_DIR}/groups.json"

##############################################
# 8. Account Management and User Status (AC-2)
##############################################
echo "8) Retrieving user account information and lifecycle states..."

# Check users by status
echo "8a) Retrieving users by account status..."
for status in ACTIVE LOCKED_OUT PASSWORD_EXPIRED RECOVERY SUSPENDED DEPROVISIONED; do
  echo "   - Status: $status"
  encoded_status=$(printf "%s" "$status" | jq -sRr @uri)
  okta_get "https://${OKTA_DOMAIN}/api/v1/users?limit=200&filter=status%20eq%20%22${encoded_status}%22" \
    "${OUTPUT_DIR}/users_${status}.json"
done

# Check account lifecycle policies (AC-2)
echo "8b) Retrieving user lifecycle policies..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=USER_LIFECYCLE" \
  "${OUTPUT_DIR}/user_lifecycle_policies.json"

# Check inactive users (AC-2(3))
echo "8c) Retrieving potentially inactive users..."
INACTIVE_DATE=$(date -u -d '90 days ago' +"%Y-%m-%dT%H:%M:%SZ" | jq -sRr @uri)
okta_get "https://${OKTA_DOMAIN}/api/v1/users?filter=lastLogin+lt+\"${INACTIVE_DATE}\"&limit=200" \
  "${OUTPUT_DIR}/inactive_users.json"

tee "${OUTPUT_DIR}/account_management_info.txt" <<EOF
User account files:
- users_*.json: Users by account status
- user_lifecycle_policies.json: Account lifecycle management policies
- inactive_users.json: Users who haven't logged in for 90+ days

Relevant NIST 800-53 Controls:
- AC-2: Account Management
- AC-2(3): Disable Inactive Accounts
EOF

##############################################
# 9. Password Policies and Authenticator Management (IA-5)
##############################################
echo "9) Retrieving password and authenticator management policies..."

# Get password policies 
echo "9a) Retrieving password policies..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
  "${OUTPUT_DIR}/password_policies.json"

# Get all policy rules for detailed analysis
echo "9b) Retrieving detailed password policy rules..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
  "${OUTPUT_DIR}/password_policies_temp.json"

# For each password policy, get its rules
jq -r '.[].id' "${OUTPUT_DIR}/password_policies_temp.json" | while read -r policy_id; do
  echo "   - Getting rules for policy ${policy_id}..."
  okta_get "https://${OKTA_DOMAIN}/api/v1/policies/${policy_id}/rules" \
    "${OUTPUT_DIR}/password_policy_rules_${policy_id}.json"
done

rm -f "${OUTPUT_DIR}/password_policies_temp.json"

# Evaluate authentication lockout settings (AC-7)
echo "9c) Retrieving authentication failure handling settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/brands" \
  "${OUTPUT_DIR}/brands.json"

tee "${OUTPUT_DIR}/password_policy_guidance.txt" <<EOF
Password policy files:
- password_policies.json: Main password policies
- password_policy_rules_*.json: Specific rules for each policy

NIST SP 800-63B Recommendations:
- Minimum length of 8 characters (12+ recommended)
- No composition rules requiring specific character types
- No mandatory periodic rotation
- Check against breached password lists
- Allow paste in password fields
- Use of secure password managers

Relevant NIST 800-53 Controls:
- IA-5: Authenticator Management
- AC-7: Unsuccessful Login Attempts
EOF

##############################################
# 11. Okta SIEM Integration & Monitoring
##############################################
echo "11) Retrieving System Log events and monitoring configuration..."

# Get recent system logs 
echo "11a) Retrieving recent system log events (last 24 hours)..."
SINCE=$(date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%SZ")
okta_get "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000" \
  "${OUTPUT_DIR}/system_log_recent.json"

# Get failed login attempts (AU-2, AC-7)
echo "11b) Retrieving failed login attempts (last 24 hours)..."
okta_get "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000&filter=eventType+eq+\"user.authentication.auth_via_mfa\"" \
  "${OUTPUT_DIR}/failed_authentication_attempts.json"

# Get admin actions for audit (AU-2)
echo "11c) Retrieving administrator actions (last 24 hours)..."
okta_get "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000&filter=eventType+sw+\"system.\"" \
  "${OUTPUT_DIR}/admin_actions.json"

tee "${OUTPUT_DIR}/system_log_readme.txt" <<EOF
The system log files contain events starting from ${SINCE}.
- system_log_recent.json: General system events (up to 1000 events)
- failed_authentication_attempts.json: Failed authentication attempts
- admin_actions.json: Administrator actions in the system

For a full log, implement pagination as documented here:
https://developer.okta.com/docs/reference/api/system-log/#pagination

Relevant NIST 800-53 Controls:
- AU-2: Audit Events
- AC-7: Unsuccessful Login Attempts
- SI-4: Information System Monitoring
EOF

##############################################
# 12. Okta Behavioral Detection and Threat Insight Settings
##############################################
echo "12) Behavioral Detection and Threat Insight Settings..."
echo "For Behavioral Detection, please verify in Admin UI or see policy references in sign_on_policies.json" \
  | tee "${OUTPUT_DIR}/behavior_detection_readme.txt"

# Retrieve Threat Insight Settings (including Network Zone exemptions)
echo "12a) Retrieving Threat Insight Settings (including exempt Network Zones)..."
okta_get "https://${OKTA_DOMAIN}/api/v1/threats/configuration" \
  "${OUTPUT_DIR}/threat_insight_settings.json"

# Check if there are network zones configured
echo "12b) Retrieving Network Zones (for cross-referencing Threat Insight exemptions)..."
okta_get "https://${OKTA_DOMAIN}/api/v1/zones" \
  "${OUTPUT_DIR}/network_zones.json"

##############################################
# 13. Okta Notifications and Emails
##############################################
echo "13) Retrieving Email Templates (for reference)..."
if ! okta_get "https://${OKTA_DOMAIN}/api/v1/templates/email" "${OUTPUT_DIR}/email_templates.json"; then
  echo "Warning: Could not retrieve email templates. Possibly not enabled in this tenant." \
    | tee "${OUTPUT_DIR}/email_templates_error.txt"
fi

##############################################
# 14. Okta API Token Evaluation
##############################################
echo "14) SSWS API tokens can only be listed in the Admin UI (Security → API → Tokens)." \
  | tee "${OUTPUT_DIR}/api_token_evaluation_readme.txt"

##############################################
# 15. Okta Federal Subscription Validation
##############################################
echo "15) Confirm subscription FedRAMP High via domain (.okta.gov/.okta.mil) and procurement docs." \
  | tee "${OUTPUT_DIR}/federal_subscription_readme.txt"

##############################################
# FedRAMP Controls Compliance Summary Generator 
##############################################
echo "Creating FedRAMP compliance summary report..."

tee "${OUTPUT_DIR}/fedramp_compliance_summary.md" <<EOF
# Okta FedRAMP Compliance Audit Summary
Generated: $(date)
Domain: ${OKTA_DOMAIN}

## NIST 800-53 Controls Coverage

| Control | Description | Files to Review | Compliance Notes |
|---------|-------------|-----------------|------------------|
| AC-2 | Account Management | users_*.json, user_lifecycle_policies.json, inactive_users.json | Review user provisioning, status tracking, and inactive account handling |
| AC-3 | Access Enforcement | sign_on_policies.json, access_policies.json | Review policy enforcement for resources |
| AC-7 | Unsuccessful Login Attempts | password_policies.json, failed_authentication_attempts.json | Check lockout settings and recent failures |
| AC-11 | Session Lock | session_info.json, authorization_servers.json | Review session timeout settings |
| IA-2 | Identification and Authentication | mfa_enrollment_policies.json, sign_on_policies.json | Verify MFA enforcement |
| IA-5 | Authenticator Management | password_policies.json, authenticators.json | Review password and authenticator settings |
| IA-8 | Identification and Authentication (Non-organizational Users) | mfa_enrollment_policies.json | Verify consistency in auth requirements |
| AU-2 | Audit Events | system_log_recent.json, admin_actions.json | Review logging coverage |
| SI-4 | Information System Monitoring | threat_insight_settings.json, network_zones.json | Check security monitoring |

## FedRAMP-Specific Considerations
1. Domain check: ${OKTA_DOMAIN} should be .okta.gov or .okta.mil
2. FIDO2/WebAuthn settings should be enforced and compliant
3. Session lifetime should meet FedRAMP requirements (typically 15-30 minutes of inactivity)
4. Password policy complexity should align with NIST SP 800-63B

## Remediation Checklist 
- [ ] Verify Threat Insight settings and exemptions are properly configured
- [ ] Confirm MFA settings align with FedRAMP requirements
- [ ] Validate session timeout configuration
- [ ] Ensure all administrator accounts have appropriate controls
- [ ] Confirm logging/monitoring meets audit requirements
- [ ] Verify FIDO2 configuration meets requirements

EOF

##############################################
# Zip everything up
##############################################
ZIPFILE="okta_audit_${TIMESTAMP}.zip"
zip -r "$ZIPFILE" "$OUTPUT_DIR" >/dev/null

echo
echo "All checks complete!"
echo "Results directory: $OUTPUT_DIR"
echo "Zipped archive:    $ZIPFILE"
echo "FedRAMP summary:   ${OUTPUT_DIR}/fedramp_compliance_summary.md"
