"""ISMAP compliance report generator (ISO 27001 controls)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

# ISO 27001 Annex A controls grouped by area
_ISO_CONTROLS: dict[str, list[tuple[str, str]]] = {
    "A.9.1 - Business Requirements of Access Control": [
        ("A.9.1.1", "Access control policy - formal policy documented and communicated"),
        ("A.9.1.2", "Access to networks and network services is restricted to authorized users"),
    ],
    "A.9.2 - User Access Management": [
        ("A.9.2.1", "User registration and de-registration - formal process for granting/revoking access"),
        ("A.9.2.2", "User access provisioning - formal process to assign access rights"),
        ("A.9.2.3", "Management of privileged access rights - restricted and controlled"),
        ("A.9.2.4", "Management of secret authentication information - controlled allocation"),
        ("A.9.2.5", "Review of user access rights - periodic review by asset owners"),
        ("A.9.2.6", "Removal or adjustment of access rights upon termination/change"),
    ],
    "A.9.4 - System and Application Access Control": [
        ("A.9.4.1", "Information access restriction based on access control policy"),
        ("A.9.4.2", "Secure log-on procedures - controlled by secure authentication"),
        ("A.9.4.3", "Password management system enforces quality passwords"),
        ("A.9.4.4", "Use of privileged utility programs is restricted and controlled"),
    ],
    "A.12.4 - Logging and Monitoring": [
        ("A.12.4.1", "Event logging - user activities, exceptions, and security events recorded"),
        ("A.12.4.2", "Protection of log information - tamper-proof logging"),
        ("A.12.4.3", "Administrator and operator logs - recorded and reviewed"),
        ("A.12.4.4", "Clock synchronization - consistent timestamps across systems"),
    ],
}


@register_reporter
class ISMAPReporter(ReportGenerator):
    name = "ismap_report"
    display_name = "ISMAP Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        findings_by_id: dict[str, ComplianceFinding] = {
            f.control_id: f for f in findings if f.framework == "ISMAP"
        }

        status_counts = Counter(
            findings_by_id[cid].status
            for area_controls in _ISO_CONTROLS.values()
            for cid, _ in area_controls
            if cid in findings_by_id
        )

        total_controls = sum(len(v) for v in _ISO_CONTROLS.values())

        lines: list[str] = [
            "# ISMAP Compliance Report - ISO 27001 Control Assessment",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            "**Assessment Basis:** Information System Security Management and "
            "Assessment Program (ISMAP) / ISO 27001:2013 Annex A",
            "",
            "---",
            "",
            "## Assessment Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total Controls Assessed | {total_controls} |",
            f"| Pass | {status_counts.get('pass', 0)} |",
            f"| Fail | {status_counts.get('fail', 0)} |",
            f"| Manual | {status_counts.get('manual', 0)} |",
            f"| Not Assessed | {total_controls - sum(status_counts.values())} |",
            "",
            "---",
            "",
        ]

        for area, controls in _ISO_CONTROLS.items():
            lines.append(f"## {area}")
            lines.append("")
            lines.append("| Status | Control | Requirement | Severity | Evidence / Comments |")
            lines.append("|--------|---------|-------------|----------|-------------------|")

            for control_id, description in controls:
                finding = findings_by_id.get(control_id)
                if finding:
                    status = finding.status.upper()
                    severity = finding.severity
                    comments = finding.comments.replace("|", "/").replace("\n", " ")
                else:
                    status = "NOT ASSESSED"
                    severity = "-"
                    comments = "Requires manual assessment by ISMAP assessor"

                lines.append(
                    f"| {status} | {control_id} | {description} | {severity} | {comments} |"
                )

            lines.append("")

        # Environment context
        lines.extend([
            "---",
            "",
            "## Environment Context",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Users | {len(data.users)} |",
            f"| Groups | {len(data.groups)} |",
            f"| Applications | {len(data.apps)} |",
            f"| Authenticators | {len(data.authenticators)} |",
            f"| Identity Providers | {len(data.idps)} |",
            f"| Network Zones | {len(data.network_zones)} |",
            f"| Event Hooks | {len(data.event_hooks)} |",
            f"| Log Streams | {len(data.log_streams)} |",
            "",
            "---",
            "",
            "## ISMAP Assessment Notes",
            "",
            "### Scope",
            "This assessment covers Okta Identity-as-a-Service (IDaaS) controls "
            "relevant to the ISMAP framework. The following areas are within scope:",
            "",
            "- **A.9 Access Control** - User authentication, authorization, and session management",
            "- **A.12.4 Logging and Monitoring** - Audit logging and event monitoring",
            "",
            "### Limitations",
            "- Controls related to physical security (A.11) are managed by Okta as the "
            "cloud service provider",
            "- Organizational policy controls (A.5, A.6) require review of internal documentation",
            "- Cryptographic controls (A.10) should be validated against Okta's SOC 2 report",
            "- Human resource security (A.7) controls require HR process review",
            "",
            "### Evidence Sources",
            "- Okta API responses (users, groups, policies, authenticators)",
            "- Policy configuration analysis (session, password, MFA enrollment)",
            "- Log stream and event hook configuration",
            "",
            "### Recommendations",
            "",
            "1. **Access Reviews (A.9.2.5):** Implement quarterly access reviews using "
            "Okta's access certification capabilities or a third-party IGA solution.",
            "2. **Privileged Access (A.9.2.3):** Enforce separate admin accounts with "
            "phishing-resistant MFA and just-in-time access.",
            "3. **Log Protection (A.12.4.2):** Forward logs to an immutable SIEM to "
            "ensure tamper-proof audit trails.",
            "4. **De-provisioning (A.9.2.6):** Automate user de-provisioning on "
            "termination via HR system integration.",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "ismap", "ismap_compliance_report.md",
        )
