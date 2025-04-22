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

### Manual Evaluation Guide

For detailed manual console walkthroughs, API command examples, comprehensive checklists, and security best practices, see [okta-evaluation-guide.md](okta-evaluation-guide.md).

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
For detailed audit checklist and manual evaluation steps, see [okta-evaluation-guide.md](okta-evaluation-guide.md).
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