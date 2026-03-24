"""SOC 2 Trust Services Criteria report generator."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

# SOC 2 CC6 controls
_CC6_CONTROLS: list[tuple[str, str, str]] = [
    (
        "CC6.1",
        "Logical Access Security Software",
        "The entity implements logical access security software, infrastructure, "
        "and architectures over protected information assets to protect them from "
        "security events.",
    ),
    (
        "CC6.2",
        "User Access Provisioning",
        "Prior to issuing system credentials and granting system access, the entity "
        "registers and authorizes new internal and external users.",
    ),
    (
        "CC6.3",
        "Role-Based Access and Least Privilege",
        "The entity authorizes, modifies, or removes access to data, software, "
        "functions, and other protected information assets based on roles, "
        "responsibilities, or the principle of least privilege.",
    ),
    (
        "CC6.4",
        "Access Restriction to Physical Assets",
        "The entity restricts physical access to facilities and protected information "
        "assets to authorized personnel.",
    ),
    (
        "CC6.5",
        "Disposal of Protected Assets",
        "The entity discontinues logical and physical protections over physical assets "
        "only after the ability to read or recover data and software from those assets "
        "has been diminished.",
    ),
    (
        "CC6.6",
        "Logical Access Security Measures",
        "The entity implements logical access security measures to protect against "
        "threats from sources outside its system boundaries.",
    ),
    (
        "CC6.7",
        "Access Restriction to System Changes",
        "The entity restricts the transmission, movement, and removal of information "
        "to authorized internal and external users and processes.",
    ),
    (
        "CC6.8",
        "Malicious Software Prevention",
        "The entity implements controls to prevent or detect and act upon the "
        "introduction of unauthorized or malicious software.",
    ),
]


@register_reporter
class SOC2Reporter(ReportGenerator):
    name = "soc2_report"
    display_name = "SOC 2 Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        findings_by_id: dict[str, ComplianceFinding] = {
            f.control_id: f for f in findings if f.framework == "SOC 2"
        }

        status_counts = Counter(
            findings_by_id[cid].status
            for cid, _, _ in _CC6_CONTROLS
            if cid in findings_by_id
        )

        total = len(_CC6_CONTROLS)

        lines: list[str] = [
            "# SOC 2 Compliance Report - Trust Services Criteria Assessment",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            "**Assessment Basis:** AICPA Trust Services Criteria (TSC) - "
            "Common Criteria 6 (CC6) Logical and Physical Access Controls",
            "",
            "---",
            "",
            "## Assessment Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Total CC6 Controls | {total} |",
            f"| Pass | {status_counts.get('pass', 0)} |",
            f"| Fail | {status_counts.get('fail', 0)} |",
            f"| Manual | {status_counts.get('manual', 0)} |",
            f"| Not Assessed | {total - sum(status_counts.values())} |",
            "",
            "---",
            "",
            "## CC6 - Logical and Physical Access Controls",
            "",
        ]

        for control_id, title, description in _CC6_CONTROLS:
            finding = findings_by_id.get(control_id)

            lines.append(f"### {control_id}: {title}")
            lines.append("")
            lines.append(f"**Requirement:** {description}")
            lines.append("")

            if finding:
                status = finding.status.upper()
                severity = finding.severity
                comments = finding.comments

                match finding.status:
                    case "pass":
                        badge = "PASS"
                    case "fail":
                        badge = "FAIL"
                    case "manual":
                        badge = "MANUAL REVIEW REQUIRED"
                    case _:
                        badge = finding.status.upper()

                lines.extend([
                    f"**Status:** {badge}  ",
                    f"**Severity:** {severity}  ",
                    "",
                    f"**Assessment:** {comments}",
                ])
            else:
                lines.extend([
                    "**Status:** NOT ASSESSED  ",
                    "",
                    "**Assessment:** This control requires manual assessment by a "
                    "qualified SOC 2 auditor. API-based evidence collection is not "
                    "sufficient for this control.",
                ])

            lines.append("")
            lines.append("---")
            lines.append("")

        # Okta evidence summary
        lines.extend([
            "## Okta Environment Evidence",
            "",
            "The following data points were collected as evidence for the assessment:",
            "",
            "| Evidence Area | Details |",
            "|---------------|---------|",
            f"| Total Users | {len(data.users)} |",
            f"| Groups | {len(data.groups)} |",
            f"| Applications | {len(data.apps)} |",
            f"| Authenticators | {len(data.authenticators)} |",
            f"| Sign-On Policies | {len(data.sign_on_policies)} |",
            f"| Password Policies | {len(data.password_policies)} |",
            f"| MFA Enrollment Policies | {len(data.mfa_enrollment_policies)} |",
            f"| Network Zones | {len(data.network_zones)} |",
            f"| Event Hooks | {len(data.event_hooks)} |",
            f"| Log Streams | {len(data.log_streams)} |",
            "",
            "---",
            "",
            "## Additional TSC Criteria (Informational)",
            "",
            "While this report focuses on CC6, the following Trust Services Criteria "
            "are also relevant to Okta configurations:",
            "",
            "| Criteria | Area | Okta Relevance |",
            "|----------|------|---------------|",
            "| CC6.1-CC6.8 | Logical/Physical Access | **Primary** - covered in this report |",
            "| CC7.1-CC7.5 | System Operations | Monitoring, incident detection |",
            "| CC8.1 | Change Management | Configuration change controls |",
            "| CC9.1-CC9.2 | Risk Mitigation | Risk assessment and vendor management |",
            "",
            "---",
            "",
            "## Recommendations",
            "",
        ])

        recs: list[str] = []

        fail_controls = [
            cid for cid, _, _ in _CC6_CONTROLS
            if cid in findings_by_id and findings_by_id[cid].status == "fail"
        ]
        if fail_controls:
            recs.append(
                f"1. **Remediate failing controls:** {', '.join(fail_controls)} "
                "require immediate attention."
            )

        manual_controls = [
            cid for cid, _, _ in _CC6_CONTROLS
            if cid in findings_by_id and findings_by_id[cid].status == "manual"
        ]
        if manual_controls:
            recs.append(
                f"{len(recs) + 1}. **Complete manual assessments:** "
                f"{', '.join(manual_controls)} need human review."
            )

        recs.extend([
            f"{len(recs) + 1}. **Implement continuous monitoring:** Configure Okta "
            "event hooks or log streams to forward security events to a SIEM for "
            "CC7 compliance.",
            f"{len(recs) + 1}. **Establish access review cadence:** Perform quarterly "
            "user access reviews to demonstrate ongoing CC6.2 and CC6.3 compliance.",
            f"{len(recs) + 1}. **Document policies:** Ensure all access control policies "
            "referenced by Okta configurations are formally documented and approved.",
        ])

        for rec in recs:
            lines.append(rec)

        lines.extend([
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "soc2", "soc2_compliance_report.md",
        )
