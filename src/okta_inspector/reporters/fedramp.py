"""FedRAMP FIPS compliance report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import register_reporter
from okta_inspector.reporters.base import ReportGenerator


@register_reporter
class FedRAMPReporter(ReportGenerator):
    name = "fedramp_report"
    display_name = "FedRAMP Report"

    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        domain = data.domain

        # Domain classification
        is_gov = domain.endswith(".okta.gov")
        is_mil = domain.endswith(".okta.mil")
        if is_gov:
            domain_status = "PASS - .okta.gov domain detected (FedRAMP-authorized environment)"
        elif is_mil:
            domain_status = "PASS - .okta.mil domain detected (FedRAMP-authorized environment)"
        else:
            domain_status = (
                "WARNING - Non-government domain detected. For FedRAMP compliance, "
                "organizations should use Okta for Government (.okta.gov / .okta.mil)."
            )

        # Collect authenticator information
        authenticator_lines: list[str] = []
        has_fido2 = False
        has_okta_verify = False
        has_sms = False
        has_email = False
        has_smart_card = False

        for auth in data.authenticators:
            key = auth.get("key", "unknown")
            name = auth.get("name", "Unknown")
            auth_type = auth.get("type", "unknown")
            status = auth.get("status", "unknown")
            provider = auth.get("provider", {})
            provider_type = provider.get("type", "unknown") if isinstance(provider, dict) else "unknown"

            authenticator_lines.append(
                f"  Name:     {name}\n"
                f"  Key:      {key}\n"
                f"  Type:     {auth_type}\n"
                f"  Status:   {status}\n"
                f"  Provider: {provider_type}\n"
            )

            if key in ("webauthn", "security_key"):
                has_fido2 = True
            elif key == "okta_verify":
                has_okta_verify = True
            elif key == "phone_number":
                has_sms = True
            elif key == "okta_email":
                has_email = True
            elif key in ("smart_card_idp", "custom_otp"):
                has_smart_card = True

        # FedRAMP-relevant findings
        fedramp_findings = [f for f in findings if f.framework == "FedRAMP"]
        pass_count = sum(1 for f in fedramp_findings if f.status == "pass")
        fail_count = sum(1 for f in fedramp_findings if f.status == "fail")
        manual_count = sum(1 for f in fedramp_findings if f.status == "manual")

        # Build report
        lines: list[str] = [
            "=" * 70,
            "  FIPS COMPLIANCE REPORT - FedRAMP Assessment",
            "=" * 70,
            "",
            f"Audit Timestamp:  {ts}",
            f"Okta Domain:      {domain}",
            "",
            "-" * 70,
            "SECTION 1: DOMAIN VERIFICATION",
            "-" * 70,
            "",
            f"Domain: {domain}",
            f"Status: {domain_status}",
            "",
            "FedRAMP requires the use of FIPS 140-2 validated cryptographic",
            "modules. Okta for Government environments (.okta.gov / .okta.mil)",
            "are deployed on FIPS-validated infrastructure.",
            "",
            "-" * 70,
            "SECTION 2: CONFIGURED AUTHENTICATORS",
            "-" * 70,
            "",
        ]

        if authenticator_lines:
            for idx, block in enumerate(authenticator_lines, 1):
                lines.append(f"Authenticator #{idx}:")
                lines.append(block)
        else:
            lines.append("  No authenticators found.")
        lines.append("")

        lines.extend([
            "-" * 70,
            "SECTION 3: FIPS 140-2 AUTHENTICATOR ASSESSMENT",
            "-" * 70,
            "",
            "FIPS 140-2 Approved Authenticators:",
        ])

        fips_items: list[tuple[str, bool, str]] = [
            ("FIDO2/WebAuthn (Security Key)", has_fido2,
             "FIDO2 keys use FIPS-validated cryptographic modules"),
            ("Okta Verify (Push/TOTP)", has_okta_verify,
             "Okta Verify supports FIPS mode on government environments"),
            ("Smart Card / PIV / CAC", has_smart_card,
             "PKI-based authentication using FIPS-validated certificates"),
        ]
        for label, present, note in fips_items:
            marker = "[CONFIGURED]" if present else "[NOT CONFIGURED]"
            lines.append(f"  {marker} {label}")
            lines.append(f"            {note}")
            lines.append("")

        lines.extend([
            "Non-FIPS Authenticators (assess risk for FedRAMP):",
        ])
        non_fips: list[tuple[str, bool, str]] = [
            ("SMS/Voice", has_sms,
             "SMS is NOT recommended for FedRAMP - consider phishing-resistant alternatives"),
            ("Email OTP", has_email,
             "Email OTP is NOT FIPS-validated - acceptable only as backup factor"),
        ]
        for label, present, note in non_fips:
            if present:
                lines.append(f"  [WARNING]  {label} - CONFIGURED")
                lines.append(f"             {note}")
                lines.append("")

        lines.extend([
            "",
            "-" * 70,
            "SECTION 4: FEDRAMP FINDINGS SUMMARY",
            "-" * 70,
            "",
            f"  Total FedRAMP findings: {len(fedramp_findings)}",
            f"  Pass:   {pass_count}",
            f"  Fail:   {fail_count}",
            f"  Manual: {manual_count}",
            "",
        ])

        if fail_count > 0:
            lines.append("  Failed Controls:")
            for f in fedramp_findings:
                if f.status == "fail":
                    lines.append(f"    - {f.control_id}: {f.title} [{f.severity}]")
                    lines.append(f"      {f.comments}")
            lines.append("")

        lines.extend([
            "-" * 70,
            "SECTION 5: RECOMMENDATIONS",
            "-" * 70,
            "",
        ])

        recommendations: list[str] = []
        if not (is_gov or is_mil):
            recommendations.append(
                "1. Migrate to Okta for Government (.okta.gov) for FedRAMP authorization."
            )
        if has_sms:
            recommendations.append(
                f"{'2' if recommendations else '1'}. Disable SMS/Voice authentication "
                "and transition to phishing-resistant authenticators (FIDO2, PIV/CAC)."
            )
        if not has_fido2:
            recommendations.append(
                f"{len(recommendations) + 1}. Enable FIDO2/WebAuthn security keys "
                "for FIPS 140-2 compliant phishing-resistant MFA."
            )
        if not has_smart_card:
            recommendations.append(
                f"{len(recommendations) + 1}. Consider enabling PIV/CAC smart card "
                "authentication for government personnel."
            )
        recommendations.append(
            f"{len(recommendations) + 1}. Review all authenticator configurations "
            "against NIST SP 800-63B guidelines."
        )
        recommendations.append(
            f"{len(recommendations) + 1}. Ensure Okta system logs are forwarded "
            "to a FedRAMP-authorized SIEM solution."
        )

        for rec in recommendations:
            lines.append(f"  {rec}")
        lines.append("")

        lines.extend([
            "=" * 70,
            f"  Report generated: {ts}",
            "=" * 70,
            "",
        ])

        output.save_text("\n".join(lines), "compliance", "fips_compliance_report.txt")
