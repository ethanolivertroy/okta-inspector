#!/usr/bin/env bash
#
# okta_audit.sh
#
# A script to retrieve key Okta configuration and logs for a FedRAMP assessment.
# Requires:
#   - Bash 4+ (for associative arrays if needed)
#   - jq (for JSON pretty-printing)
#   - zip
#
# Usage:
#   Run this script:
#     ./okta_audit.sh
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

##############################################
# 2. Okta Management Console Login Evaluation
##############################################
echo "2) Retrieving Sign-On Policies..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=OKTA_SIGN_ON" \
  "${OUTPUT_DIR}/sign_on_policies.json"

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
# 8. Status of Okta Users
##############################################
echo "8) Retrieving users by status..."

for status in ACTIVE LOCKED_OUT PASSWORD_EXPIRED RECOVERY SUSPENDED DEPROVISIONED; do
  echo "   - Status: $status"
  encoded_status=$(printf "%s" "$status" | jq -sRr @uri)
  okta_get "https://${OKTA_DOMAIN}/api/v1/users?limit=200&filter=status%20eq%20%22${encoded_status}%22" \
    "${OUTPUT_DIR}/users_${status}.json"
done

##############################################
# 9. Okta Global Password Policy
##############################################
echo "9) Retrieving password policies..."
okta_get "https://${OKTA_DOMAIN}/api/v1/policies?type=PASSWORD" \
  "${OUTPUT_DIR}/password_policies.json"

##############################################
# 11. Okta SIEM Integration & Monitoring
##############################################
echo "11) Retrieving System Log events (last 24 hours example)..."
SINCE=$(date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%SZ")
okta_get "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=1000" \
  "${OUTPUT_DIR}/system_log_recent.json"

tee "${OUTPUT_DIR}/system_log_readme.txt" <<EOF
The 'system_log_recent.json' file contains up to 1000 events starting from ${SINCE}.
For a full log, implement pagination as documented here:
https://developer.okta.com/docs/reference/api/system-log/#pagination
EOF

##############################################
# 12. Okta Behavioral Detection
##############################################
echo "12) Behavioral Detection..."
echo "For Behavioral Detection, please verify in Admin UI or see policy references in sign_on_policies.json" \
  | tee "${OUTPUT_DIR}/behavior_detection_readme.txt"

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
# Zip everything up
##############################################
ZIPFILE="okta_audit_${TIMESTAMP}.zip"
zip -r "$ZIPFILE" "$OUTPUT_DIR" >/dev/null

echo
echo "All checks complete!"
echo "Results directory: $OUTPUT_DIR"
echo "Zipped archive:    $ZIPFILE"
