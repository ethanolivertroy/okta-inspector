"""IRAP (ISM + Essential Eight) framework analyzer."""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_monitoring,
    analyze_password_policies,
    find_admin_groups,
    is_mfa_enforced,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "IRAP"


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
                }
            )
    return results


@register_analyzer
class IRAPAnalyzer(FrameworkAnalyzer):
    name = "irap"
    display_name = "IRAP (ISM + Essential Eight)"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        pw_policies = analyze_password_policies(data)
        monitoring = analyze_monitoring(data)
        sessions = _extract_session_settings(data)
        admin_groups = find_admin_groups(data)

        # ================================================================
        # ISM Controls
        # ================================================================

        # -- ISM-1546: Session idle timeout > 15 min -----------------------
        if sessions:
            for s in sessions:
                idle = s.get("idle_minutes")
                if idle is not None and idle > 15:
                    findings.append(
                        _finding(
                            "ISM-1546",
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
                            "ISM-1546",
                            "Session idle timeout within ISM limit",
                            "medium",
                            "pass",
                            f"Idle timeout is {idle} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "ISM-1546",
                    "Session idle timeout",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session settings manually.",
                )
            )

        # -- ISM-0421: Password complexity (min 14, all complexity) --------
        for pp in pw_policies:
            issues: list[str] = []
            if pp.min_length < 14:
                issues.append(f"min length {pp.min_length} (need 14)")
            if not pp.complexity_met:
                issues.append("not all complexity flags enabled")
            if issues:
                findings.append(
                    _finding(
                        "ISM-0421",
                        "Password complexity does not meet ISM requirements",
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
                        "ISM-0421",
                        "Password complexity meets ISM requirements",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' min length {pp.min_length}, full complexity.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("ISM-0421", "Password complexity", "medium", "manual", "No password policies found.")
            )

        # -- ISM-1173: Account lockout threshold > 5 -----------------------
        for pp in pw_policies:
            if pp.max_attempts > 5:
                findings.append(
                    _finding(
                        "ISM-1173",
                        "Account lockout threshold exceeds 5 attempts",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' allows {pp.max_attempts} attempts (max 5).",
                        max_attempts=pp.max_attempts,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "ISM-1173",
                        "Account lockout threshold within ISM limit",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' locks after {pp.max_attempts} attempts.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("ISM-1173", "Account lockout", "medium", "manual", "No password policies found.")
            )

        # -- ISM-0407: Log streams configured ------------------------------
        if monitoring.active_log_streams:
            findings.append(
                _finding(
                    "ISM-0407",
                    "Log streams configured",
                    "high",
                    "pass",
                    f"{len(monitoring.active_log_streams)} active log stream(s).",
                )
            )
        else:
            findings.append(
                _finding(
                    "ISM-0407",
                    "Log streams not configured",
                    "high",
                    "fail",
                    "No active log streams found; event logs may not be forwarded.",
                )
            )

        # -- ISM-0072: .gov.au domain check --------------------------------
        domain_lower = data.domain.lower()
        if ".gov.au" in domain_lower:
            findings.append(
                _finding(
                    "ISM-0072",
                    "Government domain detected",
                    "medium",
                    "pass",
                    f"Domain '{data.domain}' contains .gov.au.",
                )
            )
        else:
            findings.append(
                _finding(
                    "ISM-0072",
                    "Non-government domain in use",
                    "medium",
                    "fail",
                    f"Domain '{data.domain}' does not contain .gov.au; "
                    "verify the tenant meets IRAP requirements.",
                )
            )

        # -- ISM-0974: MFA enforcement -------------------------------------
        mfa_ok = is_mfa_enforced(data)
        if mfa_ok:
            findings.append(
                _finding(
                    "ISM-0974",
                    "Multi-factor authentication enforced",
                    "high",
                    "pass",
                    "Access policies indicate MFA is enforced.",
                )
            )
        else:
            findings.append(
                _finding(
                    "ISM-0974",
                    "Multi-factor authentication not enforced",
                    "high",
                    "fail",
                    "No access policy requiring MFA was found.",
                )
            )

        # -- ISM-1175: Admin privilege restriction -------------------------
        total_groups = len(data.groups)
        admin_count = len(admin_groups)
        if total_groups > 0 and admin_count > 0:
            ratio = admin_count / total_groups
            if ratio > 0.5:
                findings.append(
                    _finding(
                        "ISM-1175",
                        "High proportion of admin groups",
                        "medium",
                        "fail",
                        f"{admin_count}/{total_groups} groups are admin groups "
                        f"({ratio:.0%}); review privilege assignment.",
                        admin_groups=admin_count,
                        total_groups=total_groups,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "ISM-1175",
                        "Admin privilege appears restricted",
                        "medium",
                        "pass",
                        f"{admin_count}/{total_groups} groups are admin groups.",
                    )
                )
        else:
            findings.append(
                _finding(
                    "ISM-1175",
                    "Admin privilege restriction",
                    "medium",
                    "manual",
                    "Unable to assess admin group ratio; verify manually.",
                )
            )

        # ================================================================
        # Essential Eight
        # ================================================================

        # -- E8-AppControl: Application control ----------------------------
        if data.apps:
            findings.append(
                _finding(
                    "E8-AppControl",
                    "Application catalog exists",
                    "medium",
                    "pass",
                    f"{len(data.apps)} application(s) managed in Okta; "
                    "verify that only approved applications are provisioned.",
                )
            )
        else:
            findings.append(
                _finding(
                    "E8-AppControl",
                    "No applications found",
                    "medium",
                    "manual",
                    "No applications returned from Okta; verify application control posture.",
                )
            )

        # -- E8-MFA: MFA enforcement (Essential Eight) ---------------------
        if mfa_ok:
            findings.append(
                _finding(
                    "E8-MFA",
                    "MFA enforcement (Essential Eight)",
                    "high",
                    "pass",
                    "MFA enforcement detected via access policies.",
                )
            )
        else:
            findings.append(
                _finding(
                    "E8-MFA",
                    "MFA not enforced (Essential Eight)",
                    "high",
                    "fail",
                    "MFA enforcement not detected; Essential Eight Maturity Level 1 requires MFA.",
                )
            )

        # -- E8-AdminPriv: Admin privilege restriction (Essential Eight) ----
        if admin_count > 0 and total_groups > 0:
            findings.append(
                _finding(
                    "E8-AdminPriv",
                    "Admin groups identified for privilege restriction",
                    "medium",
                    "pass",
                    f"{admin_count} admin group(s) identified; verify least-privilege assignment.",
                )
            )
        else:
            findings.append(
                _finding(
                    "E8-AdminPriv",
                    "Admin privilege restriction assessment",
                    "medium",
                    "manual",
                    "No admin groups detected or no groups found; verify admin privilege posture.",
                )
            )

        return findings
