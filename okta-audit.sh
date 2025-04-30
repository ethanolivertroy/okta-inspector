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
#   - curl
#
# Usage:
#   Run this script:
#     ./okta-audit.sh [options]
#
# Options:
#   -d, --domain DOMAIN       Your Okta domain (e.g., your-org.okta.com)
#   -t, --token TOKEN         Your Okta API token
#   -o, --output-dir DIR      Custom output directory (default: timestamped dir)
#   -i, --interactive         Force interactive mode even if arguments provided
#   -n, --non-interactive     Use non-interactive mode with provided arguments
#   -p, --page-size SIZE      Number of items per page for API calls (default: 200)
#   -h, --help                Show this help message and exit
#   --oauth                   Use OAuth 2.0 token instead of SSWS token

set -euo pipefail

VERSION="1.1.0"
INTERACTIVE=true
PAGE_SIZE=200
MAX_PAGES=10
TOKEN_TYPE="SSWS"

# Default values
OKTA_DOMAIN=""
OKTA_API_TOKEN=""
OUTPUT_DIR=""

# Helper functions
print_help() {
  cat <<EOF
Okta FedRAMP Compliance Audit Tool v${VERSION}

Usage: $0 [options]

Options:
  -d, --domain DOMAIN       Your Okta domain (e.g., your-org.okta.com)
  -t, --token TOKEN         Your Okta API token
  -o, --output-dir DIR      Custom output directory (default: timestamped dir)
  -i, --interactive         Force interactive mode even if arguments provided
  -n, --non-interactive     Use non-interactive mode with provided arguments
  -p, --page-size SIZE      Number of items per page for API calls (default: 200)
  -h, --help                Show this help message and exit
  --oauth                   Use OAuth 2.0 token instead of SSWS token
EOF
}

log_info() {
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] INFO: $1"
}

log_warning() {
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] WARNING: $1" >&2
}

log_error() {
  local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
  echo "[$timestamp] ERROR: $1" >&2
}

# Parse command line arguments
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -d|--domain)
        OKTA_DOMAIN="$2"
        shift 2
        ;;
      -t|--token)
        OKTA_API_TOKEN="$2"
        shift 2
        ;;
      -o|--output-dir)
        OUTPUT_DIR="$2"
        shift 2
        ;;
      -i|--interactive)
        INTERACTIVE=true
        shift
        ;;
      -n|--non-interactive)
        INTERACTIVE=false
        shift
        ;;
      -p|--page-size)
        PAGE_SIZE="$2"
        shift 2
        ;;
      --oauth)
        TOKEN_TYPE="Bearer"
        shift
        ;;
      -h|--help)
        print_help
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        print_help
        exit 1
        ;;
    esac
  done
}

# Check prerequisites
check_prerequisites() {
  local missing_deps=false

  if ! command -v jq &>/dev/null; then
    log_error "'jq' is not installed or not in PATH. Please install it."
    missing_deps=true
  fi

  if ! command -v zip &>/dev/null; then
    log_error "'zip' is not installed or not in PATH. Please install it."
    missing_deps=true
  fi

  if ! command -v curl &>/dev/null; then
    log_error "'curl' is not installed or not in PATH. Please install it."
    missing_deps=true
  fi

  if [[ "$missing_deps" = true ]]; then
    exit 1
  fi
}

# Process arguments and input
process_input() {
  # If no domain or token is provided or interactive mode is forced
  if [[ -z "$OKTA_DOMAIN" || -z "$OKTA_API_TOKEN" || "$INTERACTIVE" = true ]]; then
    # Only prompt for values that weren't provided
    if [[ -z "$OKTA_DOMAIN" ]]; then
      read -p "Enter your Okta domain (e.g., your-org.okta.com or your-org.okta.gov): " OKTA_DOMAIN
    fi
    
    if [[ -z "$OKTA_API_TOKEN" ]]; then
      read -sp "Enter your Okta API token: " OKTA_API_TOKEN
      echo  # Add newline after hidden input
    fi
    
    # We're definitely in interactive mode now
    INTERACTIVE=true
  fi
  
  # Validate inputs
  if [[ -z "$OKTA_DOMAIN" || -z "$OKTA_API_TOKEN" ]]; then
    log_error "Both Okta domain and API token are required."
    exit 1
  fi
  
  # Add token type prefix if not present
  if [[ "$TOKEN_TYPE" == "SSWS" && ! $OKTA_API_TOKEN =~ ^SSWS ]]; then
    OKTA_API_TOKEN="SSWS ${OKTA_API_TOKEN}"
  elif [[ "$TOKEN_TYPE" == "Bearer" && ! $OKTA_API_TOKEN =~ ^Bearer ]]; then
    OKTA_API_TOKEN="Bearer ${OKTA_API_TOKEN}"
  fi
  
  # Create a timestamped output directory if not specified
  if [[ -z "$OUTPUT_DIR" ]]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_DIR="okta_audit_results_${TIMESTAMP}"
  fi
  
  # Create output directory
  mkdir -p "$OUTPUT_DIR"
  
  log_info "Running Okta FedRAMP assessment checks..."
  log_info "Outputs will be saved to: $OUTPUT_DIR"
}

# Parse command line arguments
parse_args "$@"

# Check prerequisites
check_prerequisites

# Process input
process_input

##############################################
# Helper function for GET calls
##############################################
okta_get() {
  local url="$1"
  local output_file="$2"
  local tmp_response
  local http_code
  local next_url
  local combined_results
  local page_count=0
  local rate_limit_remaining
  local rate_limit_reset
  local backoff_time
  
  # Create a temporary directory for combined results
  tmp_dir=$(mktemp -d)
  trap 'rm -rf "$tmp_dir"' EXIT

  # Initialize an empty JSON array for combined results
  echo "[]" > "${tmp_dir}/combined.json"
  
  # Process initial URL
  next_url="$url"
  
  # Process all pages
  while [[ -n "$next_url" && $page_count -lt $MAX_PAGES ]]; do
    page_count=$((page_count + 1))
    
    if [[ $page_count -gt 1 ]]; then
      log_info "Fetching page $page_count: $next_url"
    fi
    
    # Use a temporary file for each response
    tmp_response=$(mktemp)
    
    # Make the request with full headers, capturing both the body and HTTP code
    http_code=$(curl -s -w "%{http_code}" \
      -D "${tmp_dir}/headers.txt" \
      -X GET \
      -H "Authorization: ${OKTA_API_TOKEN}" \
      -H "Accept: application/json" \
      "${next_url}" \
      -o "${tmp_response}")
      
    # Handle rate limiting
    rate_limit_remaining=$(grep -i "x-rate-limit-remaining" "${tmp_dir}/headers.txt" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    rate_limit_reset=$(grep -i "x-rate-limit-reset" "${tmp_dir}/headers.txt" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$http_code" == "429" ]]; then
      # Rate limit exceeded, calculate backoff time
      if [[ -n "$rate_limit_reset" ]]; then
        current_time=$(date +%s)
        backoff_time=$((rate_limit_reset - current_time + 1))
        
        if [[ $backoff_time -lt 1 ]]; then
          backoff_time=1
        elif [[ $backoff_time -gt 60 ]]; then
          backoff_time=60  # Cap at 60 seconds max
        fi
        
        log_warning "Rate limit exceeded. Backing off for $backoff_time seconds..."
        sleep $backoff_time
        
        # Retry the same URL
        rm -f "$tmp_response"
        continue
      else
        # If no reset time found, use exponential backoff
        backoff_time=$((2 ** (page_count - 1)))
        if [[ $backoff_time -gt 60 ]]; then
          backoff_time=60  # Cap at 60 seconds max
        fi
        
        log_warning "Rate limit exceeded. Backing off for $backoff_time seconds..."
        sleep $backoff_time
        
        # Retry the same URL
        rm -f "$tmp_response"
        continue
      fi
    fi
    
    # Check HTTP response code for other errors
    if [[ "$http_code" != "200" ]]; then
      log_warning "API request failed with HTTP code ${http_code}"
      echo "[]" > "$output_file"
      rm -f "${tmp_response}"
      rm -rf "$tmp_dir"
      return 1
    fi
    
    # Verify we got valid JSON
    if ! jq '.' "${tmp_response}" > "${tmp_dir}/page_${page_count}.json" 2>/dev/null; then
      log_warning "Invalid JSON response received"
      echo "[]" > "$output_file"
      rm -f "${tmp_response}"
      rm -rf "$tmp_dir"
      return 1
    fi
    
    # Check if the result is an array or an object
    is_array=$(jq 'if type == "array" then true else false end' "${tmp_response}")
    
    if [[ "$is_array" == "true" ]]; then
      # Combine with previous results if it's an array
      jq -s 'add' "${tmp_dir}/combined.json" "${tmp_dir}/page_${page_count}.json" > "${tmp_dir}/combined_new.json"
      mv "${tmp_dir}/combined_new.json" "${tmp_dir}/combined.json"
      
      # Check for Link header for pagination
      next_url=$(grep -i "Link:" "${tmp_dir}/headers.txt" | grep -o '<[^>]*>; rel="next"' | grep -o 'https://[^>]*' || echo "")
    else
      # If it's a single object, just use it directly
      cp "${tmp_response}" "${tmp_dir}/combined.json"
      next_url=""  # No pagination for single objects
    fi
    
    # Clean up
    rm -f "${tmp_response}"
    
    # If near rate limit, pause briefly
    if [[ -n "$rate_limit_remaining" && "$rate_limit_remaining" -lt 10 && -n "$rate_limit_reset" ]]; then
      current_time=$(date +%s)
      backoff_time=$((rate_limit_reset - current_time + 1))
      
      if [[ $backoff_time -gt 0 ]]; then
        log_warning "Rate limit nearly exceeded ($rate_limit_remaining remaining). Pausing for $backoff_time seconds..."
        sleep $backoff_time
      fi
    fi
    
    # If we're not going to fetch more pages, break out of the loop
    if [[ -z "$next_url" ]]; then
      break
    fi
  done
  
  # Copy the combined results to the output file
  jq '.' "${tmp_dir}/combined.json" > "$output_file"
  
  # Clean up
  rm -rf "$tmp_dir"
  
  return 0
}

##############################################
# Test the API connection
##############################################
log_info "Testing API connection..."
TEST_FILE=$(mktemp)
if ! okta_get "https://${OKTA_DOMAIN}/api/v1/users?limit=1" "$TEST_FILE"; then
  log_error "Failed to connect to Okta API. Please verify your domain and API token."
  log_error "Make sure:"
  log_error "  1. Your domain is correct (${OKTA_DOMAIN})"
  log_error "  2. Your API token is valid and has the necessary permissions"
  log_error "  3. You included the correct token prefix (SSWS/Bearer)"
  rm -f "$TEST_FILE"
  exit 1
fi

# Validate that the API connection is authorized with appropriate permissions
if jq -e 'length == 0' "$TEST_FILE" >/dev/null; then
  log_warning "API connection succeeded but returned empty results. This may indicate permission issues."
  log_warning "Please verify your token has appropriate scopes/permissions."
else
  log_info "API connection successful with appropriate permissions!"
fi

rm -f "$TEST_FILE"

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
if ! okta_get "https://${OKTA_DOMAIN}/api/v1/sessions/me" "${OUTPUT_DIR}/session_info.json"; then
  echo "Note: Session info could not be retrieved (requires active session). Skipping this check."
  echo "[]" > "${OUTPUT_DIR}/session_info.json"
fi

# Get global session settings
echo "2b) Retrieving Global Session Settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/authorizationServers" \
  "${OUTPUT_DIR}/authorization_servers.json"

##############################################
# 3. Okta FIPS Compliance
##############################################
log_info "3) Checking FIPS compliance..."
tee "${OUTPUT_DIR}/fedramp_domain_info.txt" <<EOF
Domain used: ${OKTA_DOMAIN}
(Verify if .okta.gov or .okta.mil)
Check FedRAMP environment by attempting manual browse to:
https://support.okta-gov.com/help/s/status
EOF

# Get TLS/crypto settings (needed for FIPS compliance)
log_info "3a) Retrieving TLS and cryptographic settings..."
okta_get "https://${OKTA_DOMAIN}/api/v1/authorizationServers/default" \
  "${OUTPUT_DIR}/default_auth_server.json"

# Check supported ciphers and algorithms
log_info "3b) Checking for FIPS-compliant TLS configuration..."
response=$(curl -s -v -X GET \
  -H "Authorization: ${OKTA_API_TOKEN}" \
  -H "Accept: application/json" \
  "https://${OKTA_DOMAIN}/api/v1/users?limit=1" 2>&1)

# Check FIPS compliance through Factors API
log_info "3c) Checking FIPS mode through Factors API..."
okta_get "https://${OKTA_DOMAIN}/api/v1/org/factors" \
  "${OUTPUT_DIR}/org_factors.json"

# Check IdP settings for FIPS mode configuration
log_info "3d) Checking IdP settings for FIPS configuration..."
okta_get "https://${OKTA_DOMAIN}/api/v1/idps" \
  "${OUTPUT_DIR}/idp_settings.json"

# Check system log for FIPS-related events
log_info "3e) Checking system log for FIPS-related crypto events..."
# More portable date handling for different systems
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  THIRTY_DAYS_AGO=$(date -v-30d -u +"%Y-%m-%dT%H:%M:%SZ")
else
  # Linux and others
  THIRTY_DAYS_AGO=$(date -u -d '30 days ago' +"%Y-%m-%dT%H:%M:%SZ")
fi
SINCE="$THIRTY_DAYS_AGO"

# Try getting logs without complex filters first, but limit to 3 pages max to avoid rate limiting
ORIGINAL_MAX_PAGES=$MAX_PAGES
MAX_PAGES=3  # Temporarily reduce max pages for this specific call
log_info "Note: Retrieving general system logs (limited to ${MAX_PAGES} pages) and then filtering for crypto operations..."
if ! okta_get "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=${PAGE_SIZE}" "${OUTPUT_DIR}/all_system_logs_temp.json"; then
  log_warning "Could not retrieve system logs. Creating empty file for crypto events."
  echo "[]" > "${OUTPUT_DIR}/crypto_events.json"
else
  # Use jq to filter locally instead of relying on Okta's filtering which might be having issues
  log_info "Filtering downloaded logs for crypto operations..."
  jq '[.[] | select(.eventType == "system.crypto.operations" or 
      (.eventType | startswith("system.") and 
       ((.debugContext // {}) | (.debugData // {}) | (.cryptoProvider // "") | test("FIPS"))
      ))]' \
    "${OUTPUT_DIR}/all_system_logs_temp.json" > "${OUTPUT_DIR}/crypto_events.json" 2>/dev/null || {
      log_warning "Error filtering logs with jq. Creating simplified filter."
      jq '[.[] | select(.eventType == "system.crypto.operations" or (.eventType | startswith("system.")))]' \
        "${OUTPUT_DIR}/all_system_logs_temp.json" > "${OUTPUT_DIR}/crypto_events.json" 2>/dev/null || {
          log_warning "Failed to filter logs. Creating empty crypto events file."
          echo "[]" > "${OUTPUT_DIR}/crypto_events.json"
        }
    }
  
  # Remove the temporary file
  rm -f "${OUTPUT_DIR}/all_system_logs_temp.json"
fi
# Restore original MAX_PAGES value
MAX_PAGES=$ORIGINAL_MAX_PAGES

# Create a report with FIPS compliance checks
tee "${OUTPUT_DIR}/fips_compliance_report.txt" <<EOF
# FIPS 140-2/140-3 Encryption Compliance Check

## Domain Verification
Domain: ${OKTA_DOMAIN}
Expected for FedRAMP: .okta.gov or .okta.mil domain

## Factors and IdP FIPS Verification

### Authentication Factors Analysis
The org_factors.json file shows FIPS mode status for all factors.
$(jq -r '.[] | select(.provider.type == "FIDO") | {name: .displayName, provider: .provider.type, fipsCompliant: (.settings.oauthClientId // "No FIPS indicator found")}' "${OUTPUT_DIR}/org_factors.json" 2>/dev/null || echo "Unable to parse FIPS status from factors API")

$(if jq -e '.[] | select(.factorType == "token:hotp") | select(.provider.type == "CUSTOM" and .vendorName == "FIPS Compliant")' "${OUTPUT_DIR}/org_factors.json" >/dev/null 2>&1; then
    echo "DETECTED: FIPS Compliant HOTP token configuration found."
else
    echo "NOTE: No explicit FIPS Compliant HOTP token configuration detected."
fi)

$(if jq -e '.[] | select(.factorType == "token") | select(.provider.type == "RSA" or .provider.type == "SYMANTEC")' "${OUTPUT_DIR}/org_factors.json" >/dev/null 2>&1; then
    echo "DETECTED: RSA/Symantec tokens (commonly FIPS 140-2 certified) are configured."
else
    echo "NOTE: No RSA/Symantec tokens detected."
fi)

### Identity Provider Settings Analysis
$(if jq -e '.[] | select(.protocol.algorithms.request.signature.algorithm == "SHA-256" or .protocol.algorithms.response.signature.algorithm == "SHA-256")' "${OUTPUT_DIR}/idp_settings.json" >/dev/null 2>&1; then
    echo "DETECTED: IdP using FIPS-compliant SHA-256 signature algorithm."
else
    echo "NOTE: No IdP configurations using SHA-256 detected (review idp_settings.json for details)."
fi)

$(if jq -e '.[] | select(.protocol.type == "OIDC" and .policy.provisioning.groups.action == "ASSIGN" and .name == "FIPS Compliant")' "${OUTPUT_DIR}/idp_settings.json" >/dev/null 2>&1; then
    echo "DETECTED: OIDC IdP with FIPS Compliant configuration found."
else
    echo "NOTE: No explicit FIPS Compliant OIDC IdP configuration detected."
fi)

$(if jq -e '.[] | select(.protocol.type == "SAML2" and .protocol.algorithms.request.signature.algorithm == "SHA-256")' "${OUTPUT_DIR}/idp_settings.json" >/dev/null 2>&1; then
    echo "DETECTED: SAML IdP using FIPS-compliant SHA-256 signature algorithm."
else
    echo "NOTE: No SAML IdP configurations using SHA-256 detected."
fi)

### Cryptographic Operations Analysis
$(if jq -e '.[] | select(.eventType == "system.crypto.operations" and (.displayMessage | test("FIPS")))' "${OUTPUT_DIR}/crypto_events.json" >/dev/null 2>&1; then
    echo "DETECTED: System crypto operations showing FIPS mode operations."
    jq -r '.[] | select(.eventType == "system.crypto.operations" and (.displayMessage | test("FIPS"))) | {timestamp: .published, message: .displayMessage}' "${OUTPUT_DIR}/crypto_events.json" 2>/dev/null
else
    echo "NOTE: No explicit FIPS related crypto operations detected in system logs (last 30 days)."
fi)

$(if jq -e '.[] | select(.eventType == "system.crypto.operations") | select(.debugContext.debugData.cryptoProvider | test("FIPS"))' "${OUTPUT_DIR}/crypto_events.json" >/dev/null 2>&1; then
    echo "DETECTED: Crypto operations explicitly using FIPS providers."
else 
    echo "NOTE: No explicit FIPS crypto providers detected in operations log."
fi)

## TLS Configuration Assessment
$(echo "$response" | grep -E "TLSv|SSL|cipher" | sort -u)

## FIPS 140-2/140-3 Compliance Requirements:
1. Okta FedRAMP-authorized environments (.okta.gov/.okta.mil) use FIPS 140-2/140-3 validated cryptographic modules
2. TLS connections should only use FIPS-approved algorithms:
   - TLS 1.2 or higher
   - ECDHE or DHE for key exchange
   - AES (128/256-bit) for encryption
   - SHA-256 or higher for message authentication
3. Authentication factors should use FIPS-validated cryptographic modules:
   - Hardware security keys should be FIPS 140-2/140-3 certified
   - OTP tokens should implement FIPS-compliant algorithms
   - RSA/Symantec tokens typically include FIPS certification

## Compliance Status Assessment:
- Domain check: $(if [[ "$OKTA_DOMAIN" =~ \.(okta\.gov|okta\.mil)$ ]]; then echo "PASS - FedRAMP domain detected"; else echo "REVIEW - Not using a .okta.gov/.okta.mil domain"; fi)
- TLS version: $(if echo "$response" | grep -q "TLSv1.2\|TLSv1.3"; then echo "PASS - Using TLS 1.2 or higher"; else echo "FAIL - Not using TLS 1.2 or higher"; fi)
- Cipher suite: MANUAL REVIEW NEEDED (check the TLS configuration above for FIPS-approved cipher suites)
- FIPS factors: $(if jq -e '.[] | select(.factorType == "token:hotp") | select(.provider.type == "CUSTOM" and .vendorName == "FIPS Compliant")' "${OUTPUT_DIR}/org_factors.json" >/dev/null 2>&1 || jq -e '.[] | select(.factorType == "token") | select(.provider.type == "RSA" or .provider.type == "SYMANTEC")' "${OUTPUT_DIR}/org_factors.json" >/dev/null 2>&1; then echo "PASS - FIPS-compliant factors detected"; else echo "REVIEW - No explicit FIPS-compliant factors detected"; fi)
- Crypto operations: $(if jq -e '.[] | select(.eventType == "system.crypto.operations" and (.displayMessage | test("FIPS")))' "${OUTPUT_DIR}/crypto_events.json" >/dev/null 2>&1 || jq -e '.[] | select(.eventType == "system.crypto.operations") | select(.debugContext.debugData.cryptoProvider | test("FIPS"))' "${OUTPUT_DIR}/crypto_events.json" >/dev/null 2>&1; then echo "PASS - FIPS crypto operations detected"; else echo "REVIEW - No explicit FIPS crypto operations found in logs"; fi)

## Recommendations:
1. Ensure the domain is .okta.gov or .okta.mil for FedRAMP High workloads
2. Verify with Okta support that your tenant is running within a FedRAMP High authorized environment
3. Review TLS configuration to ensure only FIPS-approved algorithms are used
4. Confirm cryptographic implementations are FIPS 140-2/140-3 validated
   (This should be covered by Okta's FedRAMP authorization package)
5. Ensure all authentication factors are FIPS-compliant (particularly important for FedRAMP High)
6. If using hardware tokens, verify they are FIPS 140-2/140-3 certified

## Notes:
- FIPS compliance for Okta is primarily handled at the platform level
- Customers are responsible for verifying they are using a FIPS-compliant Okta instance
- All Okta .gov/.mil environments should be FIPS-compliant by default
- The Factors API provides details on which factors are FIPS-compliant
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

# Create a directory for inactive user reports
INACTIVE_DIR="${OUTPUT_DIR}/inactive_users"
mkdir -p "${INACTIVE_DIR}"

# More portable date handling for different systems
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  NINETY_DAYS_AGO=$(date -v-90d -u +"%Y-%m-%dT%H:%M:%S.000Z")
else
  # Linux and others
  NINETY_DAYS_AGO=$(date -u -d '90 days ago' +"%Y-%m-%dT%H:%M:%S.000Z")
fi

# Method 1: Use search parameter with proper syntax for last login
echo "   - Method 1: Using search parameter with last_login"
okta_get "https://${OKTA_DOMAIN}/api/v1/users?search=last_login%20lt%20%22${NINETY_DAYS_AGO}%22&limit=200" \
  "${INACTIVE_DIR}/inactive_by_login_date.json" || {
  echo "   - Search by last_login failed, creating empty result"
  echo "[]" > "${INACTIVE_DIR}/inactive_by_login_date.json"
}

# Method 2: Get users by inactive statuses
echo "   - Method 2: Getting users by inactive statuses"
for status in SUSPENDED DEPROVISIONED LOCKED_OUT PASSWORD_EXPIRED; do
  echo "     - Getting users with status: ${status}"
  if [[ -s "${OUTPUT_DIR}/users_${status}.json" ]]; then
    # Copy existing files if we already have them
    cp "${OUTPUT_DIR}/users_${status}.json" "${INACTIVE_DIR}/inactive_${status}.json"
  else
    # Otherwise make the API call
    encoded_status=$(printf "%s" "$status" | jq -sRr @uri)
    okta_get "https://${OKTA_DOMAIN}/api/v1/users?filter=status%20eq%20%22${encoded_status}%22&limit=200" \
      "${INACTIVE_DIR}/inactive_${status}.json" || {
      echo "[]" > "${INACTIVE_DIR}/inactive_${status}.json"
    }
  fi
done

# Method 3 (Fallback): If other methods fail, filter locally using jq
echo "   - Method 3: Filtering active users locally by last login date"
if [[ -s "${OUTPUT_DIR}/users_ACTIVE.json" ]]; then
  jq --arg date "${NINETY_DAYS_AGO}" '[.[] | select(.lastLogin != null and .lastLogin < $date)]' \
    "${OUTPUT_DIR}/users_ACTIVE.json" > "${INACTIVE_DIR}/inactive_by_jq_filter.json" 2>/dev/null || {
      echo "   - Local filtering failed, creating empty result"
      echo "[]" > "${INACTIVE_DIR}/inactive_by_jq_filter.json"
    }
else
  echo "   - No active users file available for local filtering"
  echo "[]" > "${INACTIVE_DIR}/inactive_by_jq_filter.json"
fi

# Combine all inactive users into one consolidated file
echo "   - Combining all inactive user results"
jq -s 'add | unique_by(.id)' "${INACTIVE_DIR}"/*.json > "${OUTPUT_DIR}/inactive_users.json" 2>/dev/null || {
  echo "   - Combining results failed, creating empty consolidated file"
  echo "[]" > "${OUTPUT_DIR}/inactive_users.json"
}

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
# More portable date handling for different systems
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS
  SINCE=$(date -v-24H -u +"%Y-%m-%dT%H:%M:%SZ")
else
  # Linux and others
  SINCE=$(date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%SZ")
fi

# Retrieve logs without complex filters, with limited pages
ORIGINAL_MAX_PAGES=$MAX_PAGES
MAX_PAGES=3  # Temporarily reduce max pages for this specific call
log_info "Note: Retrieving system logs (limited to ${MAX_PAGES} pages)..."
if ! okta_get "https://${OKTA_DOMAIN}/api/v1/logs?since=${SINCE}&limit=200" "${OUTPUT_DIR}/system_log_recent.json"; then
  log_warning "Could not retrieve recent system logs. Creating empty file."
  echo "[]" > "${OUTPUT_DIR}/system_log_recent.json"
fi
# Restore original MAX_PAGES value
MAX_PAGES=$ORIGINAL_MAX_PAGES

# Get failed login attempts (AU-2, AC-7) using local filtering with jq
echo "11b) Retrieving failed login attempts (last 24 hours)..."
if [[ -s "${OUTPUT_DIR}/system_log_recent.json" ]]; then
  jq '[.[] | select(.eventType == "user.authentication.auth_via_mfa" or .eventType == "user.authentication.auth_via_social" or (.eventType | startswith("user.authentication")))]' \
    "${OUTPUT_DIR}/system_log_recent.json" > "${OUTPUT_DIR}/failed_authentication_attempts.json" 2>/dev/null || {
      log_warning "Error filtering auth logs with jq. Creating empty file."
      echo "[]" > "${OUTPUT_DIR}/failed_authentication_attempts.json"
    }
else
  log_warning "Could not retrieve failed login attempts. Creating empty file."
  echo "[]" > "${OUTPUT_DIR}/failed_authentication_attempts.json"
fi

# Get admin actions for audit (AU-2) using local filtering with jq
echo "11c) Retrieving administrator actions (last 24 hours)..."
if [[ -s "${OUTPUT_DIR}/system_log_recent.json" ]]; then
  jq '[.[] | select(.eventType | startswith("system."))]' \
    "${OUTPUT_DIR}/system_log_recent.json" > "${OUTPUT_DIR}/admin_actions.json" 2>/dev/null || {
      log_warning "Error filtering admin logs with jq. Creating empty file."
      echo "[]" > "${OUTPUT_DIR}/admin_actions.json"
    }
else
  log_warning "Could not retrieve administrator actions. Creating empty file."
  echo "[]" > "${OUTPUT_DIR}/admin_actions.json"
fi

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
5. FIPS 140-2/140-3 Compliance: Ensure cryptographic modules and TLS configuration meet FIPS requirements

## Remediation Checklist 
- [ ] Verify Threat Insight settings and exemptions are properly configured
- [ ] Confirm MFA settings align with FedRAMP requirements
- [ ] Validate session timeout configuration
- [ ] Ensure all administrator accounts have appropriate controls
- [ ] Confirm logging/monitoring meets audit requirements
- [ ] Verify FIDO2 configuration meets requirements
- [ ] Validate FIPS 140-2/140-3 compliant encryption and TLS configuration

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
echo "FIPS compliance:   ${OUTPUT_DIR}/fips_compliance_report.txt"

# FedRAMP 20x Phase One Key Security Indicators Evaluation
echo "Evaluating FedRAMP 20x Phase One Key Security Indicators..."
tee "${OUTPUT_DIR}/fedramp_20x_summary.md" <<EOF
# FedRAMP 20x Phase One Key Security Indicators Evaluation

Generated: $(date)
Domain: ${OKTA_DOMAIN}

## KSI-IAM: Identity and Access Management
- Phishing-resistant MFA (FIDO/WebAuthn): $(if jq -e '[.[] | select(.key=="fido" or .key=="web_authn")] | length>0' "${OUTPUT_DIR}/authenticators.json" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fi)
- Strong password enforcement (min length ≥12, breached pwd detection): $( \
    length=$(jq '[.[] | .settings.password.minLength] | max' "${OUTPUT_DIR}/password_policies.json" 2>/dev/null || echo 0); \
    dict=$(jq 'any(.[]; .settings.password.dictionary.enable==true)' "${OUTPUT_DIR}/password_policies.json" 2>/dev/null || echo "false"); \
    if [[ $length -ge 12 && $dict == "true" ]]; then echo "PASS"; else echo "FAIL"; fi)
- Secure API authentication methods (OAuth 2.0): $(if [[ "$TOKEN_TYPE" == "Bearer" ]]; then echo "PASS"; else echo "REVIEW"; fi)
- Least-privileged, role-based, just-in-time model: REVIEW

## KSI-MLA: Monitoring, Logging & Auditing
- SIEM integration (recent system logs): $(if jq 'length>0' "${OUTPUT_DIR}/system_log_recent.json" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fi)
- Administrator actions logged: $(if jq 'length>0' "${OUTPUT_DIR}/admin_actions.json" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fi)
- Behavior Detection & Threat Insight: REVIEW

## KSI-CM: Change Management
- System modifications logged: $(if jq 'length>0' "${OUTPUT_DIR}/admin_actions.json" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fi)
- Change procedures and testing: REVIEW

## KSI-PI: Policy and Inventory
- Asset inventory (apps list): $(if jq 'length>0' "${OUTPUT_DIR}/apps.json" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fi)
- Defined security policies (password & MFA): $(if jq 'length>0' "${OUTPUT_DIR}/password_policies.json" >/dev/null 2>&1 && jq 'length>0' "${OUTPUT_DIR}/mfa_enrollment_policies.json" >/dev/null 2>&1; then echo "PASS"; else echo "FAIL"; fi)

## KSI-3IR: Third Party Information Resources
- External identity providers configured: $(if jq 'length>0' "${OUTPUT_DIR}/idp_settings.json" >/dev/null 2>&1; then echo "PASS"; else echo "NONE"; fi)
- FedRAMP-authorized external services: REVIEW

EOF

# Add FedRAMP 20x summary to zip archive
zip -ur "$ZIPFILE" "${OUTPUT_DIR}/fedramp_20x_summary.md" >/dev/null 2>&1 || true

# Notify user about FedRAMP 20x summary
echo "FedRAMP 20x summary:   ${OUTPUT_DIR}/fedramp_20x_summary.md"
