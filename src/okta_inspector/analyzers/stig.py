"""DISA STIG framework analyzer."""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_certificates,
    analyze_monitoring,
    analyze_password_policies,
    has_admin_console_mfa,
    has_dashboard_mfa,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "STIG"


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
    """Pull session-related settings from access policies that embed rules."""
    results: list[dict] = []
    for policy in data.access_policies:
        embedded = policy.get("_embedded", {}).get("rules", [])
        for rule in embedded:
            actions = rule.get("actions", {})
            signon = actions.get("signon", {})
            session = signon.get("session", {})
            results.append(
                {
                    "policy_name": policy.get("name", ""),
                    "rule_name": rule.get("name", ""),
                    "idle_minutes": session.get("maxSessionIdleMinutes"),
                    "lifetime_minutes": session.get("maxSessionLifetimeMinutes"),
                    "persistent_cookie": session.get("usePersistentCookie", False),
                }
            )
    return results


@register_analyzer
class STIGAnalyzer(FrameworkAnalyzer):
    name = "stig"
    display_name = "DISA STIG"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        sessions = _extract_session_settings(data)
        pw_policies = analyze_password_policies(data)
        certs = analyze_certificates(data)
        monitoring = analyze_monitoring(data)

        # -- V-273186: Session idle timeout ---------------------------------
        if sessions:
            for s in sessions:
                idle = s.get("idle_minutes")
                if idle is not None and idle > 15:
                    findings.append(
                        _finding(
                            "V-273186",
                            "Session idle timeout exceeds 15 minutes",
                            "medium",
                            "fail",
                            f"Policy '{s['policy_name']}' rule '{s['rule_name']}' "
                            f"has idle timeout of {idle} min (max 15).",
                            idle_timeout_minutes=idle,
                        )
                    )
                elif idle is not None:
                    findings.append(
                        _finding(
                            "V-273186",
                            "Session idle timeout within STIG limit",
                            "medium",
                            "pass",
                            f"Idle timeout is {idle} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "V-273186",
                    "Session idle timeout",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session settings manually.",
                )
            )

        # -- V-273203: Session lifetime -------------------------------------
        if sessions:
            for s in sessions:
                lifetime = s.get("lifetime_minutes")
                if lifetime is not None and lifetime > 1080:
                    findings.append(
                        _finding(
                            "V-273203",
                            "Session lifetime exceeds 18 hours",
                            "medium",
                            "fail",
                            f"Policy '{s['policy_name']}' rule '{s['rule_name']}' "
                            f"has lifetime of {lifetime} min (max 1080).",
                            session_lifetime_minutes=lifetime,
                        )
                    )
                elif lifetime is not None:
                    findings.append(
                        _finding(
                            "V-273203",
                            "Session lifetime within STIG limit",
                            "medium",
                            "pass",
                            f"Session lifetime is {lifetime} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "V-273203",
                    "Session lifetime",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session lifetime manually.",
                )
            )

        # -- V-273206: Persistent cookies -----------------------------------
        persistent_found = False
        for s in sessions:
            if s.get("persistent_cookie"):
                persistent_found = True
                findings.append(
                    _finding(
                        "V-273206",
                        "Persistent cookies enabled",
                        "medium",
                        "fail",
                        f"Policy '{s['policy_name']}' rule '{s['rule_name']}' "
                        "has persistent cookies enabled.",
                    )
                )
        if not persistent_found:
            findings.append(
                _finding(
                    "V-273206",
                    "Persistent cookies",
                    "medium",
                    "pass" if sessions else "manual",
                    "No persistent cookies detected."
                    if sessions
                    else "No embedded session rules found; verify manually.",
                )
            )

        # -- V-273195: Password minimum length ------------------------------
        for pp in pw_policies:
            if pp.min_length < 15:
                findings.append(
                    _finding(
                        "V-273195",
                        "Password minimum length below 15",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' requires min length {pp.min_length} (need 15).",
                        min_length=pp.min_length,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "V-273195",
                        "Password minimum length meets STIG requirement",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' requires min length {pp.min_length}.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "V-273195",
                    "Password minimum length",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- V-273189: Lockout threshold ------------------------------------
        for pp in pw_policies:
            if pp.max_attempts > 3:
                findings.append(
                    _finding(
                        "V-273189",
                        "Lockout threshold exceeds 3 attempts",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' allows {pp.max_attempts} attempts (max 3).",
                        max_attempts=pp.max_attempts,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "V-273189",
                        "Lockout threshold within STIG limit",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' allows {pp.max_attempts} attempts.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "V-273189",
                    "Lockout threshold",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- V-273201: Password max age (60 days) ---------------------------
        for pp in pw_policies:
            if pp.max_age_days != 60:
                findings.append(
                    _finding(
                        "V-273201",
                        "Password max age is not 60 days",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' has max age {pp.max_age_days} days (expected 60).",
                        max_age_days=pp.max_age_days,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "V-273201",
                        "Password max age meets STIG requirement",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' max age is {pp.max_age_days} days.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "V-273201",
                    "Password max age",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- V-273209: Password history < 5 ---------------------------------
        for pp in pw_policies:
            if pp.history_count < 5:
                findings.append(
                    _finding(
                        "V-273209",
                        "Password history below 5",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' remembers {pp.history_count} passwords (need 5).",
                        history_count=pp.history_count,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "V-273209",
                        "Password history meets STIG requirement",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' remembers {pp.history_count} passwords.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "V-273209",
                    "Password history",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- V-273193: Admin Console MFA ------------------------------------
        if has_admin_console_mfa(data):
            findings.append(
                _finding(
                    "V-273193",
                    "Admin Console MFA configured",
                    "high",
                    "pass",
                    "An access policy for Admin Console was detected.",
                )
            )
        else:
            findings.append(
                _finding(
                    "V-273193",
                    "Admin Console MFA not configured",
                    "high",
                    "fail",
                    "No Admin Console access policy detected; MFA may not be enforced for admins.",
                )
            )

        # -- V-273194: Dashboard MFA ----------------------------------------
        if has_dashboard_mfa(data):
            findings.append(
                _finding(
                    "V-273194",
                    "Dashboard MFA configured",
                    "high",
                    "pass",
                    "An access policy for the Dashboard was detected.",
                )
            )
        else:
            findings.append(
                _finding(
                    "V-273194",
                    "Dashboard MFA not configured",
                    "high",
                    "fail",
                    "No Dashboard access policy detected; MFA may not be enforced.",
                )
            )

        # -- V-273204: PIV/CAC ----------------------------------------------
        if certs.has_piv_cac:
            findings.append(
                _finding(
                    "V-273204",
                    "PIV/CAC authentication configured",
                    "medium",
                    "pass",
                    f"Found {len(certs.cert_idps)} cert IdP(s) and "
                    f"{len(certs.cert_authenticators)} cert authenticator(s).",
                )
            )
        else:
            findings.append(
                _finding(
                    "V-273204",
                    "PIV/CAC authentication not configured",
                    "medium",
                    "fail",
                    "No PIV/CAC or certificate-based IdP or authenticator found.",
                )
            )

        # -- V-273202: Log offloading ---------------------------------------
        if monitoring.active_log_streams:
            findings.append(
                _finding(
                    "V-273202",
                    "Log offloading configured",
                    "high",
                    "pass",
                    f"{len(monitoring.active_log_streams)} active log stream(s) detected.",
                )
            )
        else:
            findings.append(
                _finding(
                    "V-273202",
                    "Log offloading not configured",
                    "high",
                    "fail",
                    "No active log streams found; logs may not be offloaded to a SIEM.",
                )
            )

        return findings
