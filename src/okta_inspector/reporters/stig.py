"""DISA STIG compliance checklist report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

# All 24 STIG V-IDs organized by category
_STIG_CONTROLS: dict[str, list[tuple[str, str]]] = {
    "Session Management": [
        ("V-273186", "Okta must be configured to set the inactivity timeout"),
        ("V-273187", "Okta must be configured to set the session lifetime"),
        ("V-273189", "Okta must disable persistent cookies for session management"),
    ],
    "Authentication": [
        ("V-273190", "Okta must be configured to require MFA for user authentication"),
        ("V-273191", "Okta must enforce approved authentication methods"),
        ("V-273192", "Okta must disable weak authentication methods"),
        ("V-273193", "Okta must enforce MFA for all administrative access"),
        ("V-273194", "Okta must use phishing-resistant authenticators where feasible"),
    ],
    "MFA Enrollment": [
        ("V-273196", "Okta must require MFA enrollment for all users"),
        ("V-273197", "Okta must enforce authenticator assurance levels"),
        ("V-273198", "Okta must restrict self-service authenticator reset"),
    ],
    "Password Policy": [
        ("V-273195", "Okta must enforce minimum password length of 15 characters"),
        ("V-273199", "Okta must enforce password complexity requirements"),
        ("V-273200", "Okta must enforce password history (last 5 passwords)"),
        ("V-273201", "Okta must enforce account lockout after failed attempts"),
    ],
    "Logging and Monitoring": [
        ("V-273202", "Okta must be configured to send audit logs to a SIEM"),
        ("V-273203", "Okta must log all authentication events"),
        ("V-273204", "Okta must log all administrative configuration changes"),
        ("V-273205", "Okta must retain logs per DoD requirements"),
    ],
    "Advanced Authentication": [
        ("V-273206", "Okta must integrate with DoD PKI for certificate-based auth"),
        ("V-273207", "Okta must support PIV/CAC smart card authentication"),
        ("V-273208", "Okta must enforce certificate revocation checking (OCSP/CRL)"),
        ("V-273209", "Okta must disable legacy/deprecated authentication protocols"),
        ("V-273210", "Okta must enforce TLS 1.2 or higher for all connections"),
    ],
}


@register_reporter
class STIGReporter(ReportGenerator):
    name = "stig_report"
    display_name = "DISA STIG Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Index findings by control_id for quick lookup
        findings_by_id: dict[str, ComplianceFinding] = {}
        for f in findings:
            if f.framework == "DISA STIG":
                findings_by_id[f.control_id] = f

        total_controls = sum(len(v) for v in _STIG_CONTROLS.values())
        assessed = 0
        pass_count = 0
        fail_count = 0
        manual_count = 0
        na_count = 0

        lines: list[str] = [
            "# DISA STIG Compliance Checklist",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            f"**Total V-IDs:** {total_controls}",
            "",
            "---",
            "",
            "## Status Legend",
            "",
            "| Symbol | Meaning |",
            "|--------|---------|",
            "| :white_check_mark: PASS | Control requirement is satisfied |",
            "| :x: FAIL | Control requirement is not met |",
            "| :warning: MANUAL | Requires manual verification |",
            "| :heavy_minus_sign: N/A | Not applicable to this environment |",
            "| :question: NOT ASSESSED | No automated check available |",
            "",
            "---",
            "",
        ]

        for category, controls in _STIG_CONTROLS.items():
            lines.append(f"## {category}")
            lines.append("")
            lines.append("| Status | V-ID | Requirement | Severity | Comments |")
            lines.append("|--------|------|-------------|----------|----------|")

            for vid, description in controls:
                finding = findings_by_id.get(vid)
                if finding:
                    assessed += 1
                    status = finding.status
                    severity = finding.severity
                    comments = finding.comments.replace("|", "/").replace("\n", " ")

                    match status:
                        case "pass":
                            symbol = "PASS"
                            pass_count += 1
                        case "fail":
                            symbol = "FAIL"
                            fail_count += 1
                        case "manual":
                            symbol = "MANUAL"
                            manual_count += 1
                        case "not_applicable":
                            symbol = "N/A"
                            na_count += 1
                        case _:
                            symbol = "ERROR"
                else:
                    symbol = "NOT ASSESSED"
                    severity = "-"
                    comments = "No automated check available for this V-ID"

                lines.append(
                    f"| {symbol} | {vid} | {description} | {severity} | {comments} |"
                )

            lines.append("")

        # Summary
        lines.extend([
            "---",
            "",
            "## Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total V-IDs | {total_controls} |",
            f"| Assessed | {assessed} |",
            f"| Pass | {pass_count} |",
            f"| Fail | {fail_count} |",
            f"| Manual | {manual_count} |",
            f"| Not Applicable | {na_count} |",
            f"| Not Assessed | {total_controls - assessed} |",
            "",
        ])

        # Manual verification section
        lines.extend([
            "---",
            "",
            "## Manual Verification Required",
            "",
            "The following items require manual assessment by a qualified "
            "STIG assessor and cannot be fully validated via the Okta API:",
            "",
            "### Physical and Environmental",
            "- Verify Okta's FedRAMP authorization documentation for physical controls",
            "- Confirm data-at-rest encryption via Okta's SOC 2 report",
            "",
            "### Certificate-Based Authentication (V-273206 through V-273208)",
            "- Verify PKI integration with DoD certificate authorities",
            "- Test PIV/CAC card authentication end-to-end",
            "- Confirm OCSP/CRL responder configuration and failover behavior",
            "",
            "### TLS Configuration (V-273210)",
            "- Verify TLS 1.2+ enforcement via network scan (e.g., `nmap --script ssl-enum-ciphers`)",
            "- Confirm deprecated TLS versions and weak cipher suites are disabled",
            "",
            "### Log Retention (V-273205)",
            "- Verify SIEM retention meets DoD requirements (typically 1 year online, 5 years archive)",
            "- Confirm log integrity controls are in place",
            "",
            "### Administrative Procedures",
            "- Review account provisioning and deprovisioning procedures",
            "- Verify separation of duties for administrative accounts",
            "- Confirm incident response procedures reference Okta audit logs",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "disa_stig", "stig_compliance_checklist.md",
        )
