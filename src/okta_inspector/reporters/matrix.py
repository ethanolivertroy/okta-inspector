"""Unified compliance matrix report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator


@register_reporter
class UnifiedComplianceMatrixReporter(ReportGenerator):
    name = "matrix"
    display_name = "Unified Compliance Matrix"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: list[str] = [
            "# Unified Compliance Matrix",
            "",
            f"**Generated:** {ts}  ",
            f"**Domain:** {data.domain}",
            "",
            "This matrix shows how each security control area maps across all "
            "assessed compliance frameworks. Each row references the detailed "
            "analysis files for that control area.",
            "",
            "---",
            "",
            "## Cross-Framework Control Mapping",
            "",
            "| Control Area | FedRAMP | DISA STIG | IRAP (ISM) | ISMAP (ISO 27001) "
            "| SOC 2 | PCI-DSS | CMMC 2.0 | Analysis File |",
            "|---|---|---|---|---|---|---|---|---|",
            # Session Management
            "| **Session Management** | AC-11 | V-273186 | ISM-1546 | A.9.4.2 "
            "| CC6.6 | 8.2.8 | AC.L2-3.1.10 | `analysis/session_analysis.json` |",
            # Authentication
            "| **Authentication** | IA-2 | V-273193 | ISM-0974 | A.9.4.2 "
            "| CC6.1 | 8.3.1 | IA.L2-3.5.3 | `analysis/authenticator_analysis.json` |",
            # Password Policy
            "| **Password Policy** | IA-5 | V-273195 | ISM-0421 | A.9.2.4 "
            "| CC6.1 | 8.3.6 | IA.L2-3.5.7 | `analysis/password_policy_analysis.json` |",
            # Account Management
            "| **Account Management** | AC-2 | V-273188 | ISM-1175 | A.9.2.1 "
            "| CC6.2 | 7.1.1 | AC.L2-3.1.5 | `analysis/user_analysis.json` |",
            # Monitoring
            "| **Monitoring** | AU-4 | V-273202 | ISM-0407 | A.12.4.1 "
            "| CC7.2 | 10.2.1 | AU.L2-3.3.1 | `analysis/monitoring_analysis.json` |",
            "",
            "---",
            "",
            "## Detailed Control Descriptions",
            "",
            "### 1. Session Management",
            "",
            "| Framework | Control ID | Requirement |",
            "|-----------|-----------|-------------|",
            "| FedRAMP | AC-11 | Session lock after inactivity period |",
            "| DISA STIG | V-273186 | Session timeout enforcement |",
            "| IRAP | ISM-1546 | Session timeouts for inactive users |",
            "| ISMAP | A.9.4.2 | Secure log-on procedures |",
            "| SOC 2 | CC6.6 | Logical access security measures |",
            "| PCI-DSS | 8.2.8 | Session timeout after 15 minutes of inactivity |",
            "| CMMC | AC.L2-3.1.10 | Session lock |",
            "",
            "**Analysis:** See `analysis/session_analysis.json` for current "
            "session timeout configuration and persistent cookie settings.",
            "",
            "### 2. Authentication",
            "",
            "| Framework | Control ID | Requirement |",
            "|-----------|-----------|-------------|",
            "| FedRAMP | IA-2 | Identification and authentication (Organizational Users) |",
            "| DISA STIG | V-273193 | Multi-factor authentication enforcement |",
            "| IRAP | ISM-0974 | Multi-factor authentication for privileged access |",
            "| ISMAP | A.9.4.2 | Secure log-on procedures |",
            "| SOC 2 | CC6.1 | Logical access security software |",
            "| PCI-DSS | 8.3.1 | MFA for all non-console administrative access |",
            "| CMMC | IA.L2-3.5.3 | Multi-factor authentication |",
            "",
            "**Analysis:** See `analysis/authenticator_analysis.json` for "
            "configured authenticators and MFA enrollment policies.",
            "",
            "### 3. Password Policy",
            "",
            "| Framework | Control ID | Requirement |",
            "|-----------|-----------|-------------|",
            "| FedRAMP | IA-5 | Authenticator management |",
            "| DISA STIG | V-273195 | Password complexity and lifecycle |",
            "| IRAP | ISM-0421 | Passphrase and password requirements |",
            "| ISMAP | A.9.2.4 | Management of secret authentication information |",
            "| SOC 2 | CC6.1 | Logical access security software |",
            "| PCI-DSS | 8.3.6 | Minimum password complexity |",
            "| CMMC | IA.L2-3.5.7 | Password complexity |",
            "",
            "**Analysis:** See `analysis/password_policy_analysis.json` for "
            "current password policy settings including length, complexity, "
            "history, and lockout thresholds.",
            "",
            "### 4. Account Management",
            "",
            "| Framework | Control ID | Requirement |",
            "|-----------|-----------|-------------|",
            "| FedRAMP | AC-2 | Account management |",
            "| DISA STIG | V-273188 | Account lifecycle management |",
            "| IRAP | ISM-1175 | Access management and review |",
            "| ISMAP | A.9.2.1 | User registration and de-registration |",
            "| SOC 2 | CC6.2 | User access provisioning |",
            "| PCI-DSS | 7.1.1 | Access control policy definition |",
            "| CMMC | AC.L2-3.1.5 | Least privilege |",
            "",
            "**Analysis:** See `analysis/user_analysis.json` for user status "
            "breakdown and inactive account identification.",
            "",
            "### 5. Monitoring",
            "",
            "| Framework | Control ID | Requirement |",
            "|-----------|-----------|-------------|",
            "| FedRAMP | AU-4 | Audit log storage capacity |",
            "| DISA STIG | V-273202 | Audit log configuration and retention |",
            "| IRAP | ISM-0407 | Event logging requirements |",
            "| ISMAP | A.12.4.1 | Event logging |",
            "| SOC 2 | CC7.2 | Monitoring of system components |",
            "| PCI-DSS | 10.2.1 | Audit trail implementation |",
            "| CMMC | AU.L2-3.3.1 | System auditing |",
            "",
            "**Analysis:** See `analysis/monitoring_analysis.json` for event "
            "hooks, log stream configuration, and recent log event summary.",
            "",
            "---",
            "",
            "## Manual Verification Required",
            "",
            "The following controls cannot be fully assessed via the Okta API "
            "and require manual verification by a qualified assessor:",
            "",
            "| Area | Controls | Verification Method |",
            "|------|----------|-------------------|",
            "| Physical Security | PE-* / ISM-0810 | On-site inspection of Okta data center SLAs |",
            "| Incident Response | IR-* / ISM-0123 | Review of organizational IR procedures |",
            "| Personnel Security | PS-* / ISM-0434 | HR process review and background check verification |",
            "| Configuration Management | CM-* / ISM-1407 | Review of change management procedures |",
            "| Risk Assessment | RA-* / A.12.6.1 | Organizational risk register review |",
            "",
            "---",
            "",
            "## How to Use This Matrix",
            "",
            "1. **Identify overlapping controls** - A single remediation may "
            "satisfy requirements across multiple frameworks.",
            "2. **Prioritize by coverage** - Controls that appear in more "
            "frameworks should be remediated first.",
            "3. **Reference analysis files** - Each row links to the detailed "
            "JSON analysis for that control area.",
            "4. **Track remediation** - Use this matrix as a checklist for "
            "ongoing compliance monitoring.",
            "",
            "---",
            f"*Generated on {ts}*",
            "",
        ]

        output.save_markdown("\n".join(lines), "compliance", "unified_compliance_matrix.md")
