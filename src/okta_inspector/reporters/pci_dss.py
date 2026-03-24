"""PCI-DSS compliance report generator (Requirements 7 and 8)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

# PCI-DSS v4.0 Requirements 7 & 8 controls
_PCI_CONTROLS: dict[str, list[tuple[str, str]]] = {
    "Requirement 7: Restrict Access to System Components and Cardholder Data by Business Need to Know": [
        ("7.1.1", "Security policies and operational procedures for restricting access are documented and enforced"),
        ("7.1.2", "Access control model is defined with appropriate grant/revoke processes"),
        ("7.2.1", "Access control system is configured to enforce need-to-know restrictions"),
        ("7.2.2", "Access is assigned based on job classification and function"),
        ("7.2.3", "Required privileges are approved by authorized personnel"),
        ("7.2.4", "Access control systems are configured to enforce least privilege"),
        ("7.2.5", "Access to system components is assigned and managed appropriately"),
        ("7.2.6", "Access rights are reviewed at least semi-annually"),
    ],
    "Requirement 8: Identify Users and Authenticate Access to System Components": [
        ("8.1.1", "Security policies for identification and authentication are documented and enforced"),
        ("8.2.1", "All users are assigned unique IDs for system access"),
        ("8.2.2", "Group, shared, or generic accounts are managed as exceptions"),
        ("8.2.3", "Service accounts and application accounts are managed securely"),
        ("8.2.4", "User accounts are managed through their lifecycle"),
        ("8.2.5", "Access for terminated users is immediately revoked"),
        ("8.2.6", "Inactive accounts are removed or disabled within 90 days"),
        ("8.2.7", "Third-party access accounts are managed appropriately"),
        ("8.2.8", "Session idle timeout is set to 15 minutes or less"),
        ("8.3.1", "All user access is authenticated with at least one factor"),
        ("8.3.2", "Strong cryptography renders all authentication factors unreadable"),
        ("8.3.4", "Failed authentication attempts are limited and accounts locked"),
        ("8.3.5", "Passwords/passphrases meet minimum complexity requirements"),
        ("8.3.6", "Passwords are at least 12 characters (or 8 if system limitation)"),
        ("8.3.7", "Users change password at least every 90 days"),
        ("8.3.8", "Authentication policies are enforced for all access"),
        ("8.3.9", "Passwords are not the same as previous 4 passwords"),
        ("8.3.10", "MFA is implemented for all access into the CDE"),
        ("8.3.11", "Physical and/or logical tokens are managed appropriately"),
        ("8.4.1", "MFA is implemented for all non-console administrative access"),
        ("8.4.2", "MFA is implemented for all access into the CDE"),
        ("8.4.3", "MFA is implemented for all remote network access"),
        ("8.5.1", "MFA implementation is not susceptible to replay attacks"),
        ("8.6.1", "System and application accounts are managed based on least privilege"),
        ("8.6.2", "Passwords for system/application accounts are changed periodically"),
        ("8.6.3", "Passwords for system/application accounts are protected against misuse"),
    ],
}


@register_reporter
class PCIDSSReporter(ReportGenerator):
    name = "pci_dss_report"
    display_name = "PCI-DSS Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        findings_by_id: dict[str, ComplianceFinding] = {
            f.control_id: f for f in findings if f.framework == "PCI-DSS"
        }

        all_control_ids = [
            cid for controls in _PCI_CONTROLS.values() for cid, _ in controls
        ]
        status_counts = Counter(
            findings_by_id[cid].status
            for cid in all_control_ids
            if cid in findings_by_id
        )
        total = len(all_control_ids)

        lines: list[str] = [
            "# PCI-DSS Compliance Report",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            "**Assessment Basis:** PCI-DSS v4.0 - Requirements 7 and 8",
            "",
            "---",
            "",
            "## Assessment Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total Controls | {total} |",
            f"| Pass | {status_counts.get('pass', 0)} |",
            f"| Fail | {status_counts.get('fail', 0)} |",
            f"| Manual | {status_counts.get('manual', 0)} |",
            f"| Not Assessed | {total - sum(status_counts.values())} |",
            "",
            "---",
            "",
        ]

        # Detailed control assessment
        for requirement, controls in _PCI_CONTROLS.items():
            lines.append(f"## {requirement}")
            lines.append("")
            lines.append(
                "| Status | Control | Requirement | Severity | Comments |"
            )
            lines.append(
                "|--------|---------|-------------|----------|----------|"
            )

            for control_id, description in controls:
                finding = findings_by_id.get(control_id)
                if finding:
                    status = finding.status.upper()
                    severity = finding.severity
                    comments = finding.comments.replace("|", "/").replace("\n", " ")
                else:
                    status = "NOT ASSESSED"
                    severity = "-"
                    comments = "Requires manual assessment by QSA"

                lines.append(
                    f"| {status} | {control_id} | {description} | {severity} | {comments} |"
                )

            lines.append("")

        # Gap analysis
        fail_findings = [
            (cid, findings_by_id[cid])
            for cid in all_control_ids
            if cid in findings_by_id and findings_by_id[cid].status == "fail"
        ]

        lines.extend([
            "---",
            "",
            "## Gap Analysis",
            "",
        ])

        if fail_findings:
            lines.extend([
                "The following controls have been identified as failing and "
                "require remediation before PCI-DSS compliance can be achieved:",
                "",
                "| Priority | Control | Issue | Severity | Remediation |",
                "|----------|---------|-------|----------|------------|",
            ])

            for idx, (cid, finding) in enumerate(fail_findings, 1):
                issue = finding.comments.replace("|", "/").replace("\n", " ")
                # Generate remediation guidance based on control area
                if cid.startswith("8.3."):
                    remediation = "Update authentication policy configuration in Okta Admin Console"
                elif cid.startswith("8.2."):
                    remediation = "Review user lifecycle management processes and Okta provisioning settings"
                elif cid.startswith("8.4."):
                    remediation = "Enable and enforce MFA policies for the relevant user populations"
                elif cid.startswith("7."):
                    remediation = "Review and update access control policies and group assignments"
                else:
                    remediation = "Review Okta configuration and organizational procedures"

                lines.append(
                    f"| {idx} | {cid} | {issue} | {finding.severity} | {remediation} |"
                )

            lines.append("")
        else:
            lines.append("No failing controls identified in automated assessment.")
            lines.append("")

        # Remediation plan
        lines.extend([
            "---",
            "",
            "## Remediation Plan",
            "",
            "### Immediate Actions (0-30 days)",
            "",
        ])

        critical_fails = [
            (cid, f) for cid, f in fail_findings
            if f.severity in ("critical", "high")
        ]
        if critical_fails:
            for cid, f in critical_fails:
                lines.append(
                    f"- [ ] **{cid}** ({f.severity}): {f.title} - "
                    f"{f.comments.split('.')[0]}."
                )
        else:
            lines.append("- No critical or high-severity items requiring immediate action.")
        lines.append("")

        lines.extend([
            "### Short-Term Actions (30-90 days)",
            "",
        ])

        medium_fails = [
            (cid, f) for cid, f in fail_findings
            if f.severity == "medium"
        ]
        if medium_fails:
            for cid, f in medium_fails:
                lines.append(f"- [ ] **{cid}** ({f.severity}): {f.title}")
        else:
            lines.append("- No medium-severity items identified.")
        lines.append("")

        lines.extend([
            "### Ongoing Actions",
            "",
            "- [ ] Establish semi-annual access review process (Req. 7.2.6)",
            "- [ ] Implement continuous monitoring for authentication anomalies",
            "- [ ] Document all access control exceptions and obtain management approval",
            "- [ ] Conduct quarterly reviews of system and application account privileges",
            "- [ ] Maintain evidence of MFA enforcement for all CDE access",
            "",
            "---",
            "",
            "## QSA Assessment Notes",
            "",
            "This automated assessment provides evidence collection and preliminary "
            "control evaluation. A Qualified Security Assessor (QSA) should:",
            "",
            "1. Validate automated findings against current Okta configuration",
            "2. Assess organizational policies and procedures not visible via API",
            "3. Verify physical access controls (Req. 7 physical components)",
            "4. Test authentication mechanisms end-to-end",
            "5. Review compensating controls for any identified gaps",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "pci_dss", "pci_dss_compliance_report.md",
        )
