"""CMMC 2.0 compliance report generator."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

# CMMC 2.0 Level 2 practices by domain (Okta-relevant subset)
_CMMC_PRACTICES: dict[str, list[tuple[str, str, int]]] = {
    "AC - Access Control": [
        ("AC.L2-3.1.1", "Limit system access to authorized users, processes, and devices", 5),
        ("AC.L2-3.1.2", "Limit system access to authorized transaction types and functions", 5),
        ("AC.L2-3.1.3", "Control the flow of CUI in accordance with approved authorizations", 3),
        ("AC.L2-3.1.4", "Separate duties of individuals to reduce risk of malicious activity", 3),
        ("AC.L2-3.1.5", "Employ the principle of least privilege", 5),
        ("AC.L2-3.1.6", "Use non-privileged accounts for non-security functions", 3),
        ("AC.L2-3.1.7", "Prevent non-privileged users from executing privileged functions", 5),
        ("AC.L2-3.1.8", "Limit unsuccessful logon attempts", 3),
        ("AC.L2-3.1.9", "Provide privacy and security notices consistent with CUI rules", 1),
        ("AC.L2-3.1.10", "Use session lock with pattern-hiding displays", 3),
        ("AC.L2-3.1.11", "Terminate user sessions after defined conditions", 3),
        ("AC.L2-3.1.12", "Monitor and control remote access sessions", 3),
        ("AC.L2-3.1.13", "Employ cryptographic mechanisms to protect remote access", 3),
        ("AC.L2-3.1.14", "Route remote access via managed access control points", 3),
        ("AC.L2-3.1.15", "Authorize remote execution of privileged commands", 5),
        ("AC.L2-3.1.20", "Verify and control connections to external systems", 3),
        ("AC.L2-3.1.21", "Limit use of portable storage devices", 1),
        ("AC.L2-3.1.22", "Control CUI posted or processed on publicly accessible systems", 1),
    ],
    "IA - Identification and Authentication": [
        ("IA.L2-3.5.1", "Identify system users, processes, and devices", 5),
        ("IA.L2-3.5.2", "Authenticate users, processes, and devices as a prerequisite", 5),
        ("IA.L2-3.5.3", "Use multi-factor authentication for local and network access", 5),
        ("IA.L2-3.5.4", "Employ replay-resistant authentication mechanisms", 3),
        ("IA.L2-3.5.5", "Prevent reuse of identifiers for a defined period", 1),
        ("IA.L2-3.5.6", "Disable identifiers after a defined period of inactivity", 3),
        ("IA.L2-3.5.7", "Enforce minimum password complexity and change requirements", 3),
        ("IA.L2-3.5.8", "Prohibit password reuse for a specified number of generations", 3),
        ("IA.L2-3.5.9", "Allow temporary passwords for system logons with immediate change", 1),
        ("IA.L2-3.5.10", "Store and transmit only cryptographically-protected passwords", 5),
        ("IA.L2-3.5.11", "Obscure feedback of authentication information", 1),
    ],
    "AU - Audit and Accountability": [
        ("AU.L2-3.3.1", "Create and retain system audit logs to enable monitoring", 5),
        ("AU.L2-3.3.2", "Ensure actions of individual users can be uniquely traced", 5),
        ("AU.L2-3.3.3", "Review and update logged events", 1),
        ("AU.L2-3.3.4", "Alert in the event of an audit logging process failure", 3),
        ("AU.L2-3.3.5", "Correlate audit record review, analysis, and reporting", 3),
        ("AU.L2-3.3.6", "Provide audit record reduction and report generation", 1),
        ("AU.L2-3.3.7", "Provide a system capability for comparing and synchronizing clocks", 1),
        ("AU.L2-3.3.8", "Protect audit information and tools from unauthorized access", 3),
        ("AU.L2-3.3.9", "Limit management of audit logging functionality to authorized users", 3),
    ],
}

# Severity weight mapping for SPRS calculation
_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 5,
    "high": 3,
    "medium": 1,
    "low": 1,
    "info": 0,
}


@register_reporter
class CMMCReporter(ReportGenerator):
    name = "cmmc_report"
    display_name = "CMMC 2.0 Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        findings_by_id: dict[str, ComplianceFinding] = {
            f.control_id: f for f in findings if f.framework == "CMMC"
        }

        all_practice_ids = [
            pid
            for practices in _CMMC_PRACTICES.values()
            for pid, _, _ in practices
        ]
        status_counts = Counter(
            findings_by_id[pid].status
            for pid in all_practice_ids
            if pid in findings_by_id
        )
        total = len(all_practice_ids)

        # Calculate SPRS score
        sprs_score, sprs_deductions = self._calculate_sprs(findings_by_id)

        lines: list[str] = [
            "# CMMC 2.0 Compliance Report",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            "**Assessment Basis:** Cybersecurity Maturity Model Certification (CMMC) 2.0 - Level 2  ",
            "**NIST SP 800-171 Rev 2 Mapping:** Practices align to NIST 800-171 security requirements",
            "",
            "---",
            "",
            "## Assessment Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total Practices (Okta-relevant) | {total} |",
            f"| Pass | {status_counts.get('pass', 0)} |",
            f"| Fail | {status_counts.get('fail', 0)} |",
            f"| Manual | {status_counts.get('manual', 0)} |",
            f"| Not Assessed | {total - sum(status_counts.values())} |",
            f"| **Estimated SPRS Score** | **{sprs_score} / 110** |",
            "",
            "---",
            "",
            "## Practice-by-Practice Assessment",
            "",
        ]

        # Domain-by-domain assessment tables
        for domain, practices in _CMMC_PRACTICES.items():
            lines.append(f"### {domain}")
            lines.append("")
            lines.append(
                "| Status | Practice | Requirement | Point Value | Severity | Comments |"
            )
            lines.append(
                "|--------|----------|-------------|-------------|----------|----------|"
            )

            for practice_id, description, point_value in practices:
                finding = findings_by_id.get(practice_id)
                if finding:
                    status = finding.status.upper()
                    severity = finding.severity
                    comments = finding.comments.replace("|", "/").replace("\n", " ")
                    # Truncate long comments for table readability
                    if len(comments) > 120:
                        comments = comments[:117] + "..."
                else:
                    status = "NOT ASSESSED"
                    severity = "-"
                    comments = "Requires assessment"

                lines.append(
                    f"| {status} | {practice_id} | {description} "
                    f"| {point_value} | {severity} | {comments} |"
                )

            lines.append("")

        # SPRS Score section
        lines.extend([
            "---",
            "",
            "## SPRS Score Estimate",
            "",
            "The Supplier Performance Risk System (SPRS) score is calculated "
            "starting from a baseline of 110 points, with deductions for each "
            "practice not fully implemented. The point value deducted is based "
            "on the practice's weight in NIST SP 800-171.",
            "",
            f"**Starting Score:** 110  ",
            f"**Total Deductions:** {110 - sprs_score}  ",
            f"**Estimated SPRS Score:** {sprs_score}",
            "",
        ])

        if sprs_deductions:
            lines.extend([
                "### Deduction Details",
                "",
                "| Practice | Point Value | Severity | Deduction Reason |",
                "|----------|-------------|----------|-----------------|",
            ])
            for practice_id, point_value, severity, reason in sprs_deductions:
                lines.append(
                    f"| {practice_id} | {point_value} | {severity} | {reason} |"
                )
            lines.append("")
        else:
            lines.append("No deductions - all assessed practices pass.")
            lines.append("")

        lines.extend([
            "**Note:** This is an estimate based on Okta-relevant practices only. "
            "A complete SPRS score includes all 110 NIST SP 800-171 practices across "
            "all system components, not just the identity provider.",
            "",
        ])

        # POA&M template
        poam_items = [
            (pid, findings_by_id[pid])
            for pid in all_practice_ids
            if pid in findings_by_id and findings_by_id[pid].status == "fail"
        ]

        lines.extend([
            "---",
            "",
            "## Plan of Action and Milestones (POA&M)",
            "",
            "The following POA&M items are generated for practices that failed assessment. "
            "Each item should be assigned an owner, target date, and tracked to completion.",
            "",
        ])

        if poam_items:
            lines.extend([
                "| # | Practice | Weakness | Severity | Milestone | Owner | Target Date | Status |",
                "|---|----------|----------|----------|-----------|-------|-------------|--------|",
            ])

            for idx, (pid, finding) in enumerate(poam_items, 1):
                weakness = finding.comments.replace("|", "/").replace("\n", " ")
                if len(weakness) > 80:
                    weakness = weakness[:77] + "..."

                # Suggest milestone based on severity
                match finding.severity:
                    case "critical":
                        milestone = "Immediate remediation (0-30 days)"
                    case "high":
                        milestone = "Near-term remediation (30-60 days)"
                    case "medium":
                        milestone = "Planned remediation (60-90 days)"
                    case _:
                        milestone = "Scheduled remediation (90-180 days)"

                lines.append(
                    f"| {idx} | {pid} | {weakness} | {finding.severity} "
                    f"| {milestone} | TBD | TBD | Open |"
                )

            lines.append("")
        else:
            lines.append("No POA&M items required - all assessed practices pass.")
            lines.append("")

        lines.extend([
            "### POA&M Guidance",
            "",
            "- Each POA&M item must identify the specific weakness and planned corrective action",
            "- Items must include milestones with completion dates",
            "- POA&M must be reviewed and updated at least quarterly",
            "- Critical and high severity items should be prioritized for immediate remediation",
            "- The POA&M must be submitted with SPRS score to the DoD",
            "",
        ])

        # Level 2 readiness
        assessed_count = sum(status_counts.values())
        pass_count = status_counts.get("pass", 0)
        fail_count = status_counts.get("fail", 0)

        if assessed_count > 0:
            pass_rate = pass_count / assessed_count * 100
        else:
            pass_rate = 0.0

        match pass_rate:
            case r if r >= 90:
                readiness = "HIGH"
                readiness_detail = (
                    "The Okta identity provider configuration is well-aligned with "
                    "CMMC Level 2 requirements. Minor remediation items should be "
                    "addressed via the POA&M."
                )
            case r if r >= 70:
                readiness = "MODERATE"
                readiness_detail = (
                    "The Okta configuration meets many CMMC Level 2 requirements but "
                    "has notable gaps. A focused remediation effort is recommended "
                    "before pursuing Level 2 certification."
                )
            case r if r >= 50:
                readiness = "LOW"
                readiness_detail = (
                    "Significant gaps exist in the Okta configuration relative to "
                    "CMMC Level 2 requirements. A comprehensive remediation plan "
                    "is needed before certification can be pursued."
                )
            case _:
                readiness = "NOT READY"
                readiness_detail = (
                    "The Okta configuration does not meet minimum CMMC Level 2 "
                    "requirements. Fundamental security controls must be implemented "
                    "before beginning the certification process."
                )

        lines.extend([
            "---",
            "",
            "## Level 2 Readiness Summary",
            "",
            f"**Overall Readiness:** {readiness}",
            "",
            f"**Assessment:** {readiness_detail}",
            "",
            "| Domain | Practices | Pass | Fail | Manual | Pass Rate |",
            "|--------|-----------|------|------|--------|-----------|",
        ])

        for domain, practices in _CMMC_PRACTICES.items():
            domain_total = len(practices)
            domain_pass = sum(
                1 for pid, _, _ in practices
                if pid in findings_by_id and findings_by_id[pid].status == "pass"
            )
            domain_fail = sum(
                1 for pid, _, _ in practices
                if pid in findings_by_id and findings_by_id[pid].status == "fail"
            )
            domain_manual = sum(
                1 for pid, _, _ in practices
                if pid in findings_by_id and findings_by_id[pid].status == "manual"
            )
            domain_assessed = domain_pass + domain_fail + domain_manual
            domain_rate = (
                f"{domain_pass / domain_assessed * 100:.0f}%"
                if domain_assessed > 0
                else "N/A"
            )

            lines.append(
                f"| {domain} | {domain_total} | {domain_pass} | {domain_fail} "
                f"| {domain_manual} | {domain_rate} |"
            )

        lines.extend([
            "",
            "### Key Actions for Level 2 Certification",
            "",
            "1. **Remediate all POA&M items** - Address failing practices, "
            "prioritizing critical and high severity.",
            "2. **Complete manual assessments** - Have a C3PAO-qualified assessor "
            "validate controls requiring manual review.",
            "3. **Document SSP** - Ensure the System Security Plan references "
            "Okta configuration as evidence for identity-related practices.",
            "4. **Submit SPRS score** - Calculate the complete SPRS score across "
            "all system components and submit to SPRS.",
            "5. **Engage C3PAO** - Schedule a Level 2 assessment with an authorized "
            "CMMC Third-Party Assessment Organization.",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "cmmc", "cmmc_compliance_report.md",
        )

    # ------------------------------------------------------------------

    @staticmethod
    def _calculate_sprs(
        findings_by_id: dict[str, ComplianceFinding],
    ) -> tuple[int, list[tuple[str, int, str, str]]]:
        """Estimate SPRS score. Returns (score, deduction_details)."""
        score = 110
        deductions: list[tuple[str, int, str, str]] = []

        for practices in _CMMC_PRACTICES.values():
            for practice_id, description, point_value in practices:
                finding = findings_by_id.get(practice_id)
                if finding and finding.status == "fail":
                    # Deduct based on practice point value, scaled by severity
                    severity_weight = _SEVERITY_WEIGHTS.get(finding.severity, 1)
                    deduction = min(point_value, severity_weight)
                    score -= deduction
                    reason = finding.comments.replace("|", "/").replace("\n", " ")
                    if len(reason) > 80:
                        reason = reason[:77] + "..."
                    deductions.append(
                        (practice_id, deduction, finding.severity, reason)
                    )

        # Clamp score to valid range
        score = max(-203, min(110, score))
        return score, deductions
