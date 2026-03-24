"""Executive summary report generator."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator

_FRAMEWORKS = ("FedRAMP", "DISA STIG", "IRAP", "ISMAP", "SOC 2", "PCI-DSS", "CMMC")


@register_reporter
class ExecutiveSummaryReporter(ReportGenerator):
    name = "executive"
    display_name = "Executive Summary"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # --- Aggregate metrics ---
        status_counts = Counter(f.status for f in findings)
        severity_counts = Counter(f.severity for f in findings)
        framework_counts: dict[str, Counter[str]] = {}
        for f in findings:
            framework_counts.setdefault(f.framework, Counter())
            framework_counts[f.framework][f.status] += 1

        total = len(findings)
        pass_count = status_counts.get("pass", 0)
        fail_count = status_counts.get("fail", 0)
        manual_count = status_counts.get("manual", 0)
        na_count = status_counts.get("not_applicable", 0)
        error_count = status_counts.get("error", 0)

        # Critical / high-severity failures
        critical_fails = [
            f for f in findings if f.status == "fail" and f.severity in ("critical", "high")
        ]
        top_critical = critical_fails[:5]

        # Data metrics
        user_count = len(data.users)
        group_count = len(data.groups)
        app_count = len(data.apps)
        policy_count = (
            len(data.sign_on_policies)
            + len(data.password_policies)
            + len(data.mfa_enrollment_policies)
            + len(data.access_policies)
            + len(data.user_lifecycle_policies)
        )
        authenticator_count = len(data.authenticators)

        # --- Build markdown ---
        lines: list[str] = [
            "# Executive Summary - Okta Compliance Audit",
            "",
            f"**Audit Timestamp:** {ts}",
            f"**Okta Domain:** {data.domain}",
            "",
            "---",
            "",
            "## Frameworks Assessed",
            "",
        ]
        for fw in _FRAMEWORKS:
            lines.append(f"- {fw}")
        lines.append("")

        lines.extend([
            "---",
            "",
            "## Environment Metrics",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Users | {user_count} |",
            f"| Groups | {group_count} |",
            f"| Applications | {app_count} |",
            f"| Policies | {policy_count} |",
            f"| Authenticators | {authenticator_count} |",
            "",
            "---",
            "",
            "## Findings Overview",
            "",
            f"**Total Findings:** {total}",
            "",
            "| Status | Count | Percentage |",
            "|--------|-------|------------|",
        ])
        for label, count in [
            ("Pass", pass_count),
            ("Fail", fail_count),
            ("Manual", manual_count),
            ("Not Applicable", na_count),
            ("Error", error_count),
        ]:
            pct = f"{count / total * 100:.1f}%" if total else "0.0%"
            lines.append(f"| {label} | {count} | {pct} |")

        lines.extend([
            "",
            "### Severity Breakdown",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ])
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {sev.capitalize()} | {severity_counts.get(sev, 0)} |")

        lines.extend([
            "",
            "---",
            "",
            "## Critical Items (Top 5 High-Severity Failures)",
            "",
        ])
        if top_critical:
            lines.append("| # | Framework | Control | Title | Severity |")
            lines.append("|---|-----------|---------|-------|----------|")
            for idx, f in enumerate(top_critical, 1):
                lines.append(
                    f"| {idx} | {f.framework} | {f.control_id} | {f.title} | {f.severity} |"
                )
        else:
            lines.append("No critical or high-severity failures detected.")
        lines.append("")

        lines.extend([
            "---",
            "",
            "## Framework-Specific Results",
            "",
            "| Framework | Pass | Fail | Manual | N/A | Error | Total |",
            "|-----------|------|------|--------|-----|-------|-------|",
        ])
        for fw in sorted(framework_counts):
            fc = framework_counts[fw]
            fw_total = sum(fc.values())
            lines.append(
                f"| {fw} | {fc.get('pass', 0)} | {fc.get('fail', 0)} "
                f"| {fc.get('manual', 0)} | {fc.get('not_applicable', 0)} "
                f"| {fc.get('error', 0)} | {fw_total} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## Manual Verification Items",
            "",
        ])
        manual_findings = [f for f in findings if f.status == "manual"]
        if manual_findings:
            lines.append("| Framework | Control | Title |")
            lines.append("|-----------|---------|-------|")
            for f in manual_findings:
                lines.append(f"| {f.framework} | {f.control_id} | {f.title} |")
        else:
            lines.append("No items requiring manual verification.")

        lines.extend([
            "",
            "---",
            "",
            "## Recommendations",
            "",
        ])
        if fail_count > 0:
            lines.append(
                f"1. **Address {fail_count} failing controls** - prioritize critical "
                "and high-severity items listed above."
            )
        if manual_count > 0:
            lines.append(
                f"2. **Review {manual_count} manual verification items** - these cannot "
                "be assessed via API and require human review."
            )
        lines.extend([
            "3. **Establish recurring audits** - schedule quarterly compliance scans "
            "to track remediation progress.",
            "4. **Cross-framework remediation** - many controls overlap across frameworks; "
            "a single fix may resolve multiple findings.",
            "5. **Document exceptions** - for any accepted risks, create formal "
            "risk acceptance documentation.",
            "",
            "---",
            f"*Report generated on {ts}*",
            "",
        ])

        output.save_markdown("\n".join(lines), "compliance", "executive_summary.md")
