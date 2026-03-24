"""IRAP compliance report generator (ISM controls + Essential Eight)."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

# ISM controls grouped by area
_ISM_CONTROLS: dict[str, list[tuple[str, str]]] = {
    "Access Control": [
        ("ISM-1175", "Access to systems and data is controlled based on need-to-know"),
        ("ISM-1173", "Privileged access is restricted and monitored"),
        ("ISM-1508", "Unprivileged access is controlled and audited"),
        ("ISM-1546", "Session timeouts are enforced for inactive users"),
    ],
    "Authentication": [
        ("ISM-0974", "Multi-factor authentication is used for privileged access"),
        ("ISM-1401", "Multi-factor authentication is used for remote access"),
        ("ISM-1504", "Phishing-resistant MFA is used where available"),
        ("ISM-1679", "Authentication events are logged and monitored"),
    ],
    "Password Management": [
        ("ISM-0421", "Passphrases meet minimum length and complexity requirements"),
        ("ISM-1593", "Passphrases are at least 14 characters for standard users"),
        ("ISM-0422", "Password history prevents reuse of recent passwords"),
        ("ISM-1403", "Account lockout is enforced after repeated failed attempts"),
    ],
    "Monitoring and Logging": [
        ("ISM-0407", "Event logs are collected for security-relevant events"),
        ("ISM-0859", "Audit logs are protected from unauthorized modification"),
        ("ISM-0991", "Logs are forwarded to a centralized logging facility"),
        ("ISM-1405", "Log retention meets organizational requirements"),
    ],
    "System Hardening": [
        ("ISM-1407", "System configuration changes are logged and reviewed"),
        ("ISM-0810", "Only approved software and services are enabled"),
        ("ISM-1234", "Unnecessary accounts and services are disabled"),
        ("ISM-1584", "TLS 1.2 or higher is enforced for all communications"),
    ],
}


@register_reporter
class IRAPReporter(ReportGenerator):
    name = "irap_report"
    display_name = "IRAP Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        self._generate_irap_report(findings, data, output, ts)
        self._generate_essential_eight(findings, data, output, ts)

    # ------------------------------------------------------------------
    # IRAP ISM Control Report
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_irap_report(
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
        ts: str,
    ) -> None:
        findings_by_id: dict[str, ComplianceFinding] = {
            f.control_id: f for f in findings if f.framework == "IRAP"
        }

        status_counts = Counter(
            findings_by_id[vid].status
            for area_controls in _ISM_CONTROLS.values()
            for vid, _ in area_controls
            if vid in findings_by_id
        )

        total_controls = sum(len(v) for v in _ISM_CONTROLS.values())

        lines: list[str] = [
            "# IRAP Compliance Report - ISM Control Assessment",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            f"**Assessment Basis:** Australian Government Information Security Manual (ISM)",
            "",
            "---",
            "",
            "## Assessment Summary",
            "",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Total Controls | {total_controls} |",
            f"| Pass | {status_counts.get('pass', 0)} |",
            f"| Fail | {status_counts.get('fail', 0)} |",
            f"| Manual | {status_counts.get('manual', 0)} |",
            f"| Not Assessed | {total_controls - sum(status_counts.values())} |",
            "",
            "---",
            "",
        ]

        for area, controls in _ISM_CONTROLS.items():
            lines.append(f"## {area}")
            lines.append("")
            lines.append("| Status | ISM Control | Requirement | Severity | Comments |")
            lines.append("|--------|-------------|-------------|----------|----------|")

            for ism_id, description in controls:
                finding = findings_by_id.get(ism_id)
                if finding:
                    status = finding.status.upper()
                    severity = finding.severity
                    comments = finding.comments.replace("|", "/").replace("\n", " ")
                else:
                    status = "NOT ASSESSED"
                    severity = "-"
                    comments = "Requires manual assessment"

                lines.append(
                    f"| {status} | {ism_id} | {description} | {severity} | {comments} |"
                )

            lines.append("")

        lines.extend([
            "---",
            "",
            "## IRAP Assessment Notes",
            "",
            "### Classification Considerations",
            "- This assessment covers Okta IdP controls relevant to PROTECTED-level systems",
            "- Okta's cloud infrastructure controls should be validated separately via "
            "Okta's IRAP assessment report",
            "- Physical and environmental controls are the responsibility of the "
            "cloud service provider",
            "",
            "### Assessor Guidance",
            "- Controls marked MANUAL require an IRAP assessor to validate",
            "- API-based checks provide evidence but do not constitute a full IRAP assessment",
            "- Organizational policies and procedures must be reviewed separately",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "irap", "irap_compliance_report.md",
        )

    # ------------------------------------------------------------------
    # Essential Eight Maturity Assessment
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_essential_eight(
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
        ts: str,
    ) -> None:
        # Determine MFA status from findings
        irap_findings = {f.control_id: f for f in findings if f.framework == "IRAP"}

        mfa_pass = any(
            f.status == "pass"
            for cid, f in irap_findings.items()
            if "MFA" in f.title.upper() or cid in ("ISM-0974", "ISM-1401")
        )
        phishing_resistant = any(
            f.status == "pass"
            for cid, f in irap_findings.items()
            if cid == "ISM-1504"
        )
        has_log_forwarding = any(
            f.status == "pass"
            for cid, f in irap_findings.items()
            if cid == "ISM-0991"
        )

        # Determine password quality
        pw_pass = any(
            f.status == "pass"
            for cid, f in irap_findings.items()
            if cid in ("ISM-0421", "ISM-1593")
        )

        lines: list[str] = [
            "# Essential Eight Maturity Assessment",
            "",
            f"**Audit Timestamp:** {ts}  ",
            f"**Okta Domain:** {data.domain}  ",
            f"**Assessment Basis:** ASD Essential Eight Maturity Model",
            "",
            "---",
            "",
            "## Maturity Level Definitions",
            "",
            "| Level | Description |",
            "|-------|-------------|",
            "| **ML0** | Not aligned with the mitigation strategy |",
            "| **ML1** | Partly aligned - ad hoc implementation |",
            "| **ML2** | Mostly aligned - consistent implementation |",
            "| **ML3** | Fully aligned - comprehensive implementation |",
            "",
            "---",
            "",
            "## Essential Eight Assessment (Okta-Relevant Strategies)",
            "",
            "### E1: Application Control",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Partially relevant - Okta controls access to applications |",
            f"| Applications managed | {len(data.apps)} |",
            "| Estimated Maturity | ML1 - Okta manages app access but application whitelisting "
            "is an endpoint control |",
            "",
            "**Okta Contribution:** Okta's application catalog restricts which applications "
            "users can access via SSO. Full application control requires endpoint-level controls.",
            "",
            "### E2: Patch Applications",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Limited - Okta is a SaaS platform patched by vendor |",
            "| Estimated Maturity | ML3 - Okta manages patching as a SaaS provider |",
            "",
            "**Okta Contribution:** As a SaaS service, Okta handles application patching. "
            "Organizations should verify Okta's patch management via SOC 2 report.",
            "",
            "### E3: Configure Microsoft Office Macro Settings",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Not directly relevant to Okta IdP |",
            "| Estimated Maturity | N/A |",
            "",
            "### E4: User Application Hardening",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Partially relevant via Okta browser plugin and trusted origins |",
            f"| Trusted origins configured | {len(data.trusted_origins)} |",
            "| Estimated Maturity | ML1 |",
            "",
            "### E5: Restrict Administrative Privileges",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Highly relevant - core Okta IdP capability |",
            f"| Total users | {len(data.users)} |",
            f"| Groups defined | {len(data.groups)} |",
        ]

        # Try to identify admin groups
        admin_groups = [
            g for g in data.groups
            if "admin" in g.get("profile", {}).get("name", "").lower()
        ]
        lines.append(
            f"| Admin-related groups | {len(admin_groups)} |"
        )
        admin_maturity = "ML2" if admin_groups else "ML1"
        lines.extend([
            f"| Estimated Maturity | {admin_maturity} |",
            "",
            "**Okta Contribution:** Role-based access control via groups and admin roles. "
            "Verify separation of duties and just-in-time admin access.",
            "",
            "### E6: Patch Operating Systems",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Not directly relevant - Okta is SaaS |",
            "| Estimated Maturity | ML3 - managed by Okta |",
            "",
            "### E7: Multi-Factor Authentication",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Highly relevant - core Okta IdP capability |",
            f"| Authenticators configured | {len(data.authenticators)} |",
            f"| MFA enforcement detected | {'Yes' if mfa_pass else 'No / Unclear'} |",
            f"| Phishing-resistant MFA | {'Yes' if phishing_resistant else 'No / Unclear'} |",
        ])

        if phishing_resistant:
            mfa_maturity = "ML3"
        elif mfa_pass:
            mfa_maturity = "ML2"
        else:
            mfa_maturity = "ML1"

        lines.extend([
            f"| Estimated Maturity | {mfa_maturity} |",
            "",
            "**Okta Contribution:** Okta provides the MFA infrastructure. "
            "ML3 requires phishing-resistant authenticators (FIDO2/WebAuthn) for all users.",
            "",
            "### E8: Regular Backups",
            "",
            "| Aspect | Assessment |",
            "|--------|-----------|",
            "| Relevance | Partially relevant - log and configuration backups |",
            f"| Log streams configured | {len(data.log_streams)} |",
            f"| Event hooks configured | {len(data.event_hooks)} |",
            f"| External log forwarding | {'Yes' if has_log_forwarding else 'No / Unclear'} |",
        ])

        backup_maturity = "ML2" if has_log_forwarding else "ML1"
        lines.extend([
            f"| Estimated Maturity | {backup_maturity} |",
            "",
            "**Okta Contribution:** Okta system logs should be forwarded to external "
            "storage for backup and retention. Configuration backup requires Okta's "
            "Terraform provider or API-based export.",
            "",
            "---",
            "",
            "## Overall Maturity Summary",
            "",
            "| Strategy | Maturity | Okta Relevance |",
            "|----------|----------|---------------|",
            "| E1 - Application Control | ML1 | Partial |",
            "| E2 - Patch Applications | ML3 | SaaS-managed |",
            "| E3 - Office Macros | N/A | Not relevant |",
            "| E4 - User App Hardening | ML1 | Partial |",
            f"| E5 - Restrict Admin | {admin_maturity} | High |",
            "| E6 - Patch OS | ML3 | SaaS-managed |",
            f"| E7 - MFA | {mfa_maturity} | High |",
            f"| E8 - Regular Backups | {backup_maturity} | Partial |",
            "",
            "---",
            "",
            "## Recommendations for Maturity Improvement",
            "",
            "1. **Achieve ML3 for MFA (E7):** Deploy phishing-resistant authenticators "
            "(FIDO2/WebAuthn) and enforce for all user types.",
            "2. **Improve Admin Privilege Controls (E5):** Implement just-in-time "
            "admin access and regular access reviews.",
            "3. **Strengthen Backup Posture (E8):** Configure log streaming to a "
            "dedicated SIEM with retention policies aligned to ISM requirements.",
            "4. **Application Hardening (E4):** Review trusted origins and enforce "
            "strict redirect URI validation.",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown(
            "\n".join(lines),
            "compliance", "irap", "essential_eight_assessment.md",
        )
