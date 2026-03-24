"""Validation script and quick-reference report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator


@register_reporter
class ValidationReporter(ReportGenerator):
    name = "validation"
    display_name = "Validation Script"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        self._generate_validation_script(output, ts)
        self._generate_quick_reference(output, ts)

    # ------------------------------------------------------------------

    @staticmethod
    def _generate_validation_script(output: OutputManager, ts: str) -> None:
        script = r"""#!/usr/bin/env bash
# Okta Compliance Validation Script
# Generated: """ + ts + r"""
#
# Prerequisites: jq (https://stedolan.github.io/jq/)
# Usage: ./validate_compliance.sh [output_directory]

set -euo pipefail

OUTPUT_DIR="${1:-.}"
PASS=0
FAIL=0
WARN=0

green()  { printf '\033[0;32m%s\033[0m\n' "$1"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$1"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$1"; }

check_file() {
    local file="$1"
    local desc="$2"
    if [[ -f "$file" ]]; then
        green "[PASS] $desc exists: $file"
        PASS=$((PASS + 1))
        return 0
    else
        red "[FAIL] $desc missing: $file"
        FAIL=$((FAIL + 1))
        return 1
    fi
}

check_jq() {
    local file="$1"
    local query="$2"
    local desc="$3"
    local expected="${4:-}"

    if [[ ! -f "$file" ]]; then
        yellow "[WARN] Cannot validate $desc - file missing: $file"
        WARN=$((WARN + 1))
        return 1
    fi

    local result
    result=$(jq -r "$query" "$file" 2>/dev/null) || {
        red "[FAIL] $desc - jq query failed on $file"
        FAIL=$((FAIL + 1))
        return 1
    }

    if [[ -n "$expected" ]]; then
        if [[ "$result" == "$expected" ]]; then
            green "[PASS] $desc = $result"
            PASS=$((PASS + 1))
        else
            red "[FAIL] $desc = $result (expected: $expected)"
            FAIL=$((FAIL + 1))
        fi
    else
        if [[ "$result" != "null" && "$result" != "" ]]; then
            green "[PASS] $desc = $result"
            PASS=$((PASS + 1))
        else
            yellow "[WARN] $desc = null or empty"
            WARN=$((WARN + 1))
        fi
    fi
}

echo "========================================"
echo "  Okta Compliance Validation"
echo "========================================"
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""

# --- File existence checks ---
echo "--- Core Data Files ---"
check_file "$OUTPUT_DIR/core_data/users.json" "Users data"
check_file "$OUTPUT_DIR/core_data/groups.json" "Groups data"
check_file "$OUTPUT_DIR/core_data/apps.json" "Applications data"
check_file "$OUTPUT_DIR/core_data/authenticators.json" "Authenticators data"
echo ""

echo "--- Analysis Files ---"
check_file "$OUTPUT_DIR/analysis/session_analysis.json" "Session analysis"
check_file "$OUTPUT_DIR/analysis/password_policy_analysis.json" "Password policy analysis"
check_file "$OUTPUT_DIR/analysis/monitoring_analysis.json" "Monitoring analysis"
echo ""

# --- Session analysis validation ---
echo "--- Session Configuration ---"
SESSION_FILE="$OUTPUT_DIR/analysis/session_analysis.json"
if [[ -f "$SESSION_FILE" ]]; then
    POLICY_COUNT=$(jq 'length' "$SESSION_FILE" 2>/dev/null || echo 0)
    echo "  Session policies found: $POLICY_COUNT"

    if [[ "$POLICY_COUNT" -gt 0 ]]; then
        jq -r '.[] | "  Policy: \(.policy_name) (ID: \(.policy_id))"' "$SESSION_FILE" 2>/dev/null || true
        jq -r '.[] | .rules[]? | "    Rule: \(.name) | Idle: \(.idle_timeout_minutes)m | Lifetime: \(.lifetime_minutes)m | Persistent: \(.persistent_cookies)"' "$SESSION_FILE" 2>/dev/null || true
    fi
fi
echo ""

# --- Password policy validation ---
echo "--- Password Policy Configuration ---"
PW_FILE="$OUTPUT_DIR/analysis/password_policy_analysis.json"
if [[ -f "$PW_FILE" ]]; then
    POLICY_COUNT=$(jq 'length' "$PW_FILE" 2>/dev/null || echo 0)
    echo "  Password policies found: $POLICY_COUNT"

    if [[ "$POLICY_COUNT" -gt 0 ]]; then
        # Check minimum length (FedRAMP/STIG require >= 15 for privileged, 8+ minimum)
        jq -r '.[] | "  Policy: \(.policy_name) | Min Length: \(.min_length) | History: \(.history_count) | Max Age: \(.max_age_days)d | Lockout: \(.max_attempts) attempts / \(.lockout_duration_minutes)m"' "$PW_FILE" 2>/dev/null || true

        MIN_LEN=$(jq -r '.[0].min_length // 0' "$PW_FILE" 2>/dev/null || echo 0)
        if [[ "$MIN_LEN" -ge 8 ]]; then
            green "[PASS] Minimum password length >= 8 ($MIN_LEN)"
            PASS=$((PASS + 1))
        else
            red "[FAIL] Minimum password length < 8 ($MIN_LEN)"
            FAIL=$((FAIL + 1))
        fi

        COMPLEXITY=$(jq -r '.[0] | (.require_uppercase and .require_lowercase and .require_number and .require_symbol)' "$PW_FILE" 2>/dev/null || echo false)
        if [[ "$COMPLEXITY" == "true" ]]; then
            green "[PASS] Password complexity requirements met"
            PASS=$((PASS + 1))
        else
            red "[FAIL] Password complexity requirements not fully met"
            FAIL=$((FAIL + 1))
        fi
    fi
fi
echo ""

# --- Log stream validation ---
echo "--- Monitoring Configuration ---"
MONITOR_FILE="$OUTPUT_DIR/analysis/monitoring_analysis.json"
if [[ -f "$MONITOR_FILE" ]]; then
    HOOK_COUNT=$(jq '.active_event_hooks | length' "$MONITOR_FILE" 2>/dev/null || echo 0)
    STREAM_COUNT=$(jq '.active_log_streams | length' "$MONITOR_FILE" 2>/dev/null || echo 0)

    echo "  Active event hooks: $HOOK_COUNT"
    echo "  Active log streams: $STREAM_COUNT"

    if [[ "$STREAM_COUNT" -gt 0 || "$HOOK_COUNT" -gt 0 ]]; then
        green "[PASS] External log forwarding configured"
        PASS=$((PASS + 1))
    else
        red "[FAIL] No external log forwarding configured"
        FAIL=$((FAIL + 1))
    fi
fi
echo ""

# --- Summary ---
echo "========================================"
echo "  Validation Summary"
echo "========================================"
green "  PASS: $PASS"
red "  FAIL: $FAIL"
yellow "  WARN: $WARN"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    red "Some validation checks failed. Review the output above."
    exit 1
else
    green "All validation checks passed."
    exit 0
fi
"""
        output.save_script(script, "validate_compliance.sh")

    # ------------------------------------------------------------------

    @staticmethod
    def _generate_quick_reference(output: OutputManager, ts: str) -> None:
        md = f"""# Quick Reference Guide

**Generated:** {ts}

---

## Output Directory Structure

```
okta_audit_results_<timestamp>/
|-- core_data/                    Raw Okta API data
|   |-- users.json                All user accounts
|   |-- groups.json               Group definitions
|   |-- apps.json                 Application integrations
|   |-- authenticators.json       Configured authenticators
|   |-- policies/                 Policy data by type
|   |-- network_zones.json        Network zone definitions
|   +-- ...
|
|-- analysis/                     Processed analysis results
|   |-- session_analysis.json     Session timeout settings
|   |-- password_policy_analysis.json  Password policy evaluation
|   |-- authenticator_analysis.json    MFA and authenticator review
|   |-- monitoring_analysis.json  Log streams and event hooks
|   +-- user_analysis.json        User status breakdown
|
|-- compliance/                   Framework-specific reports
|   |-- executive_summary.md      High-level findings overview
|   |-- unified_compliance_matrix.md  Cross-framework mapping
|   |-- fedramp/                  FedRAMP FIPS analysis
|   |-- disa_stig/                DISA STIG checklist
|   |-- irap/                     IRAP and Essential Eight
|   |-- ismap/                    ISMAP ISO 27001 assessment
|   |-- soc2/                     SOC 2 Trust Services report
|   |-- pci_dss/                  PCI-DSS Req. 7 & 8
|   +-- cmmc/                     CMMC 2.0 assessment
|
|-- validate_compliance.sh        Automated validation script
+-- QUICK_REFERENCE.md            This file
```

## Key Files

| File | Purpose |
|------|---------|
| `compliance/executive_summary.md` | Start here - high-level audit overview |
| `compliance/unified_compliance_matrix.md` | Cross-framework control mapping |
| `validate_compliance.sh` | Run to validate output integrity |
| `analysis/session_analysis.json` | Session timeout configuration |
| `analysis/password_policy_analysis.json` | Password policy evaluation |
| `analysis/monitoring_analysis.json` | Logging and monitoring status |

## Usage

### Run the validation script

```bash
chmod +x validate_compliance.sh
./validate_compliance.sh .
```

### Quick policy check with jq

```bash
# Check password minimum length
jq '.[].min_length' analysis/password_policy_analysis.json

# Check session timeouts
jq '.[] | .rules[] | {{name, idle_timeout_minutes, lifetime_minutes}}' analysis/session_analysis.json

# Count active log streams
jq '.active_log_streams | length' analysis/monitoring_analysis.json
```

## Compliance Frameworks Covered

| Framework | Scope | Report Location |
|-----------|-------|----------------|
| FedRAMP | FIPS 140-2 / authenticator compliance | `compliance/fedramp/` |
| DISA STIG | 24 V-ID checklist items | `compliance/disa_stig/` |
| IRAP | ISM controls + Essential Eight | `compliance/irap/` |
| ISMAP | ISO 27001 Annex A controls | `compliance/ismap/` |
| SOC 2 | CC6 Trust Services Criteria | `compliance/soc2/` |
| PCI-DSS | Requirements 7 and 8 | `compliance/pci_dss/` |
| CMMC 2.0 | AC, IA, AU practices | `compliance/cmmc/` |

---
*Generated on {ts}*
"""
        output.save_markdown(md, "QUICK_REFERENCE.md")
