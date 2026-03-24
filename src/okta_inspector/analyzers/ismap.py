"""ISMAP (ISO 27001) framework analyzer."""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_monitoring,
    analyze_password_policies,
    analyze_users,
    is_mfa_enforced,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "ISMAP"


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


@register_analyzer
class ISMAPAnalyzer(FrameworkAnalyzer):
    name = "ismap"
    display_name = "ISMAP (ISO 27001)"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        user_analysis = analyze_users(data)
        pw_policies = analyze_password_policies(data)
        monitoring = analyze_monitoring(data)

        # -- A.9.1.1: Access control policies exist -------------------------
        has_access_policies = bool(data.access_policies)
        has_signon_policies = bool(data.sign_on_policies)
        if has_access_policies or has_signon_policies:
            findings.append(
                _finding(
                    "A.9.1.1",
                    "Access control policies configured",
                    "medium",
                    "pass",
                    f"{len(data.access_policies)} access policy/ies and "
                    f"{len(data.sign_on_policies)} sign-on policy/ies found.",
                )
            )
        else:
            findings.append(
                _finding(
                    "A.9.1.1",
                    "No access control policies found",
                    "medium",
                    "fail",
                    "No access or sign-on policies detected.",
                )
            )

        # -- A.9.2.1: User de-registration (inactive users) ----------------
        inactive_count = len(user_analysis.inactive_users)
        if inactive_count > 0:
            names = [
                u.get("profile", {}).get("login", "unknown")
                for u in user_analysis.inactive_users[:10]
            ]
            findings.append(
                _finding(
                    "A.9.2.1",
                    "Inactive user accounts detected",
                    "medium",
                    "fail",
                    f"{inactive_count} user(s) inactive for 90+ days; review de-registration.",
                    inactive_count=inactive_count,
                    sample_users=names,
                )
            )
        else:
            findings.append(
                _finding(
                    "A.9.2.1",
                    "No inactive user accounts",
                    "medium",
                    "pass",
                    "All active users have logged in within the past 90 days.",
                )
            )

        # -- A.9.2.2: Group-based access provisioning ----------------------
        if data.groups:
            findings.append(
                _finding(
                    "A.9.2.2",
                    "Group-based access provisioning in use",
                    "low",
                    "pass",
                    f"{len(data.groups)} group(s) configured for access provisioning.",
                )
            )
        else:
            findings.append(
                _finding(
                    "A.9.2.2",
                    "No groups configured",
                    "low",
                    "fail",
                    "No groups found; group-based provisioning is not in effect.",
                )
            )

        # -- A.9.2.4: Password strength (min 8 + complexity) ---------------
        for pp in pw_policies:
            issues: list[str] = []
            if pp.min_length < 8:
                issues.append(f"min length {pp.min_length} (need 8)")
            if not pp.complexity_met:
                issues.append("not all complexity flags enabled")
            if issues:
                findings.append(
                    _finding(
                        "A.9.2.4",
                        "Password strength does not meet ISMAP requirements",
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
                        "A.9.2.4",
                        "Password strength meets ISMAP requirements",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' min length {pp.min_length}, full complexity.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("A.9.2.4", "Password strength", "medium", "manual", "No password policies found.")
            )

        # -- A.9.4.2: MFA for secure log-on --------------------------------
        mfa_ok = is_mfa_enforced(data)
        if mfa_ok:
            findings.append(
                _finding(
                    "A.9.4.2",
                    "MFA configured for secure log-on",
                    "high",
                    "pass",
                    "Access policies indicate MFA is enforced.",
                )
            )
        else:
            findings.append(
                _finding(
                    "A.9.4.2",
                    "MFA not configured for secure log-on",
                    "high",
                    "fail",
                    "No access policy requiring MFA was found.",
                )
            )

        # -- A.9.4.3: Lockout <= 5 and history >= 3 ------------------------
        for pp in pw_policies:
            issues = []
            if pp.max_attempts > 5:
                issues.append(f"lockout threshold {pp.max_attempts} (max 5)")
            if pp.history_count < 3:
                issues.append(f"password history {pp.history_count} (need >= 3)")
            if issues:
                findings.append(
                    _finding(
                        "A.9.4.3",
                        "Lockout/history does not meet ISMAP requirements",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}': {'; '.join(issues)}.",
                        max_attempts=pp.max_attempts,
                        history_count=pp.history_count,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "A.9.4.3",
                        "Lockout and password history meet ISMAP requirements",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' lockout at {pp.max_attempts}, "
                        f"history {pp.history_count}.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("A.9.4.3", "Lockout and history", "medium", "manual", "No password policies found.")
            )

        # -- A.12.4.1: Event logging configured -----------------------------
        if data.system_logs:
            findings.append(
                _finding(
                    "A.12.4.1",
                    "Event logging configured",
                    "medium",
                    "pass",
                    f"{len(data.system_logs)} recent system log event(s) found.",
                )
            )
        elif monitoring.active_event_hooks or monitoring.active_log_streams:
            findings.append(
                _finding(
                    "A.12.4.1",
                    "Event logging partially configured",
                    "medium",
                    "pass",
                    "Event hooks or log streams are active but no recent logs returned.",
                )
            )
        else:
            findings.append(
                _finding(
                    "A.12.4.1",
                    "Event logging not configured",
                    "medium",
                    "fail",
                    "No system log events, event hooks, or log streams found.",
                )
            )

        # -- ISMAP-GOV: .go.jp domain check --------------------------------
        domain_lower = data.domain.lower()
        if ".go.jp" in domain_lower:
            findings.append(
                _finding(
                    "ISMAP-GOV",
                    "Japanese government domain detected",
                    "low",
                    "pass",
                    f"Domain '{data.domain}' contains .go.jp.",
                )
            )
        else:
            findings.append(
                _finding(
                    "ISMAP-GOV",
                    "Non-government domain in use",
                    "low",
                    "not_applicable",
                    f"Domain '{data.domain}' does not contain .go.jp; "
                    "this may be acceptable for private-sector ISMAP assessments.",
                )
            )

        return findings
