"""FedRAMP (NIST 800-53) framework analyzer."""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_authenticators,
    analyze_certificates,
    analyze_monitoring,
    analyze_password_policies,
    analyze_users,
    has_admin_console_mfa,
    has_dashboard_mfa,
    is_mfa_enforced,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "FedRAMP"

_PHISHING_RESISTANT_KEYS = {"webauthn", "fido2", "smart_card_idp"}


def _finding(
    control_id: str,
    title: str,
    severity: str,
    status: str,
    comments: str,
    **details: object,
) -> ComplianceFinding:
    return ComplianceFinding(
        framework=_FRAMEWORK,
        control_id=control_id,
        title=title,
        severity=severity,
        status=status,
        comments=comments,
        details=dict(details),
    )


def _extract_session_settings(data: OktaData) -> list[dict]:
    results: list[dict] = []
    for policy in data.access_policies:
        for rule in policy.get("_embedded", {}).get("rules", []):
            actions = rule.get("actions", {})
            signon = actions.get("signon", {})
            session = signon.get("session", {})
            results.append(
                {
                    "policy_name": policy.get("name", ""),
                    "rule_name": rule.get("name", ""),
                    "idle_minutes": session.get("maxSessionIdleMinutes"),
                    "lifetime_minutes": session.get("maxSessionLifetimeMinutes"),
                }
            )
    return results


@register_analyzer
class FedRAMPAnalyzer(FrameworkAnalyzer):
    name = "fedramp"
    display_name = "FedRAMP (NIST 800-53)"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        user_analysis = analyze_users(data)
        pw_policies = analyze_password_policies(data)
        authenticators = analyze_authenticators(data)
        certs = analyze_certificates(data)
        monitoring = analyze_monitoring(data)
        sessions = _extract_session_settings(data)

        # -- AC-2(3): Inactive users ----------------------------------------
        inactive_count = len(user_analysis.inactive_users)
        if inactive_count > 0:
            names = [
                u.get("profile", {}).get("login", "unknown")
                for u in user_analysis.inactive_users[:10]
            ]
            findings.append(
                _finding(
                    "AC-2(3)",
                    "Inactive user accounts detected",
                    "medium",
                    "fail",
                    f"{inactive_count} user(s) inactive for 90+ days.",
                    inactive_count=inactive_count,
                    sample_users=names,
                )
            )
        else:
            findings.append(
                _finding(
                    "AC-2(3)",
                    "No inactive user accounts",
                    "medium",
                    "pass",
                    "All active users have logged in within the past 90 days.",
                )
            )

        # -- AC-7: Lockout threshold ----------------------------------------
        for pp in pw_policies:
            if pp.max_attempts > 3:
                findings.append(
                    _finding(
                        "AC-7",
                        "Account lockout threshold too high",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' allows {pp.max_attempts} attempts "
                        "(FedRAMP recommends <= 3).",
                        max_attempts=pp.max_attempts,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "AC-7",
                        "Account lockout threshold acceptable",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' locks after {pp.max_attempts} attempts.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("AC-7", "Account lockout", "medium", "manual", "No password policies found.")
            )

        # -- AC-11: Session idle timeout ------------------------------------
        if sessions:
            for s in sessions:
                idle = s.get("idle_minutes")
                if idle is not None and idle > 15:
                    findings.append(
                        _finding(
                            "AC-11",
                            "Session idle timeout exceeds 15 minutes",
                            "medium",
                            "fail",
                            f"Policy '{s['policy_name']}' rule '{s['rule_name']}' "
                            f"idle timeout is {idle} min (max 15).",
                            idle_timeout_minutes=idle,
                        )
                    )
                elif idle is not None:
                    findings.append(
                        _finding(
                            "AC-11",
                            "Session idle timeout within FedRAMP limit",
                            "medium",
                            "pass",
                            f"Idle timeout is {idle} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "AC-11",
                    "Session idle timeout",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify manually.",
                )
            )

        # -- AC-12: Session lifetime ----------------------------------------
        if sessions:
            for s in sessions:
                lifetime = s.get("lifetime_minutes")
                if lifetime is not None and lifetime > 480:
                    findings.append(
                        _finding(
                            "AC-12",
                            "Session lifetime exceeds 8 hours",
                            "medium",
                            "fail",
                            f"Policy '{s['policy_name']}' rule '{s['rule_name']}' "
                            f"lifetime is {lifetime} min (recommended max 480).",
                            session_lifetime_minutes=lifetime,
                        )
                    )
                elif lifetime is not None:
                    findings.append(
                        _finding(
                            "AC-12",
                            "Session lifetime acceptable",
                            "medium",
                            "pass",
                            f"Session lifetime is {lifetime} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "AC-12",
                    "Session lifetime",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify manually.",
                )
            )

        # -- IA-2 / IA-2(1): MFA enforcement -------------------------------
        mfa_ok = is_mfa_enforced(data)
        admin_mfa = has_admin_console_mfa(data)
        dash_mfa = has_dashboard_mfa(data)
        if mfa_ok:
            findings.append(
                _finding(
                    "IA-2",
                    "MFA enforcement detected",
                    "high",
                    "pass",
                    "Access policies indicate MFA is enforced.",
                    admin_console_mfa=admin_mfa,
                    dashboard_mfa=dash_mfa,
                )
            )
        else:
            findings.append(
                _finding(
                    "IA-2",
                    "MFA enforcement not detected",
                    "high",
                    "fail",
                    "No access policy requiring MFA was found.",
                )
            )

        if admin_mfa:
            findings.append(
                _finding("IA-2(1)", "Privileged account MFA configured", "high", "pass",
                         "Admin Console access policy detected.")
            )
        else:
            findings.append(
                _finding("IA-2(1)", "Privileged account MFA not configured", "high", "fail",
                         "No Admin Console access policy found.")
            )

        # -- IA-2(11): Phishing-resistant authentication --------------------
        active_auths = {a.key for a in authenticators if a.status == "ACTIVE"}
        phishing_resistant = active_auths & _PHISHING_RESISTANT_KEYS
        if phishing_resistant:
            findings.append(
                _finding(
                    "IA-2(11)",
                    "Phishing-resistant authenticators available",
                    "high",
                    "pass",
                    f"Found: {', '.join(sorted(phishing_resistant))}.",
                )
            )
        else:
            findings.append(
                _finding(
                    "IA-2(11)",
                    "No phishing-resistant authenticators configured",
                    "high",
                    "fail",
                    "WebAuthn / FIDO2 / SmartCard IdP not found among active authenticators.",
                )
            )

        # -- IA-5: Password complexity --------------------------------------
        for pp in pw_policies:
            issues: list[str] = []
            if pp.min_length < 12:
                issues.append(f"min length {pp.min_length} (need 12)")
            if not pp.complexity_met:
                issues.append("complexity requirements not fully enabled")
            if issues:
                findings.append(
                    _finding(
                        "IA-5",
                        "Password policy does not meet FedRAMP requirements",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}': {'; '.join(issues)}.",
                        min_length=pp.min_length,
                        complexity_met=pp.complexity_met,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "IA-5",
                        "Password policy meets FedRAMP requirements",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' min length {pp.min_length}, full complexity.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("IA-5", "Password complexity", "medium", "manual", "No password policies found.")
            )

        # -- IA-5(2): Certificate / PIV support -----------------------------
        if certs.has_piv_cac:
            findings.append(
                _finding(
                    "IA-5(2)",
                    "Certificate-based authentication configured",
                    "medium",
                    "pass",
                    f"{len(certs.cert_idps)} cert IdP(s), "
                    f"{len(certs.cert_authenticators)} cert authenticator(s).",
                )
            )
        else:
            findings.append(
                _finding(
                    "IA-5(2)",
                    "Certificate-based authentication not configured",
                    "medium",
                    "fail",
                    "No PIV/CAC or certificate IdP or authenticator found.",
                )
            )

        # -- AU-2, AU-3: Audit logging (system logs exist) ------------------
        if data.system_logs:
            findings.append(
                _finding(
                    "AU-2",
                    "Audit event logging enabled",
                    "medium",
                    "pass",
                    f"{len(data.system_logs)} recent system log event(s) found.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AU-2",
                    "No audit events found",
                    "medium",
                    "fail",
                    "System log returned no events; verify logging is enabled.",
                )
            )

        if monitoring.log_event_summary:
            findings.append(
                _finding(
                    "AU-3",
                    "Audit records contain required content",
                    "medium",
                    "pass",
                    f"{len(monitoring.log_event_summary)} distinct event type(s) recorded.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AU-3",
                    "Audit record content",
                    "medium",
                    "manual",
                    "No event types found in system logs; verify log content manually.",
                )
            )

        # -- AU-4, AU-6: Log offloading / review ----------------------------
        if monitoring.active_log_streams:
            findings.append(
                _finding(
                    "AU-4",
                    "Log storage offloading configured",
                    "high",
                    "pass",
                    f"{len(monitoring.active_log_streams)} active log stream(s).",
                )
            )
            findings.append(
                _finding(
                    "AU-6",
                    "Automated log review capability",
                    "high",
                    "pass",
                    "Log streams enable external SIEM analysis.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AU-4",
                    "Log storage offloading not configured",
                    "high",
                    "fail",
                    "No active log streams; logs may not be forwarded to external storage.",
                )
            )
            findings.append(
                _finding(
                    "AU-6",
                    "Automated log review not configured",
                    "high",
                    "fail",
                    "Without log streams, automated SIEM review is not possible.",
                )
            )

        # -- SC-13: FIPS domain check ---------------------------------------
        domain_lower = data.domain.lower()
        if domain_lower.endswith(".okta.gov") or domain_lower.endswith(".okta.mil"):
            findings.append(
                _finding(
                    "SC-13",
                    "FIPS-compliant domain detected",
                    "high",
                    "pass",
                    f"Domain '{data.domain}' uses a FedRAMP-authorized cell.",
                )
            )
        else:
            findings.append(
                _finding(
                    "SC-13",
                    "Non-FIPS domain in use",
                    "high",
                    "fail",
                    f"Domain '{data.domain}' is not an .okta.gov/.okta.mil cell. "
                    "FIPS 140-2 validated crypto may not be in effect.",
                )
            )

        # -- SI-4: Monitoring -----------------------------------------------
        hooks_or_streams = bool(monitoring.active_event_hooks or monitoring.active_log_streams)
        if hooks_or_streams:
            findings.append(
                _finding(
                    "SI-4",
                    "System monitoring configured",
                    "medium",
                    "pass",
                    f"{len(monitoring.active_event_hooks)} event hook(s), "
                    f"{len(monitoring.active_log_streams)} log stream(s) active.",
                )
            )
        else:
            findings.append(
                _finding(
                    "SI-4",
                    "System monitoring not configured",
                    "medium",
                    "fail",
                    "No active event hooks or log streams found.",
                )
            )

        return findings
