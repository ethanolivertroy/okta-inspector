"""CMMC 2.0 (Level 2) framework analyzer.

Based on NIST 800-171 Rev 2 practices that can be evaluated from Okta configuration.
"""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_authenticators,
    analyze_monitoring,
    analyze_password_policies,
    find_admin_groups,
    is_mfa_enforced,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "CMMC"

_REPLAY_RESISTANT_KEYS = {"webauthn", "fido2"}


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
class CMMCAnalyzer(FrameworkAnalyzer):
    name = "cmmc"
    display_name = "CMMC 2.0 (Level 2)"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        pw_policies = analyze_password_policies(data)
        authenticators = analyze_authenticators(data)
        monitoring = analyze_monitoring(data)
        sessions = _extract_session_settings(data)
        admin_groups = find_admin_groups(data)

        # -- AC.L2-3.1.8: Unsuccessful logon limits (lockout <= 3) ---------
        for pp in pw_policies:
            if pp.max_attempts > 3:
                findings.append(
                    _finding(
                        "AC.L2-3.1.8",
                        "Lockout threshold exceeds 3 attempts",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' allows {pp.max_attempts} attempts "
                        "(CMMC requires <= 3).",
                        max_attempts=pp.max_attempts,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "AC.L2-3.1.8",
                        "Lockout threshold within CMMC limit",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' locks after {pp.max_attempts} attempts.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "AC.L2-3.1.8",
                    "Unsuccessful logon limits",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- AC.L2-3.1.10: Session lock after inactivity (idle <= 15 min) --
        if sessions:
            for s in sessions:
                idle = s.get("idle_minutes")
                if idle is not None and idle > 15:
                    findings.append(
                        _finding(
                            "AC.L2-3.1.10",
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
                            "AC.L2-3.1.10",
                            "Session idle timeout within CMMC limit",
                            "medium",
                            "pass",
                            f"Idle timeout is {idle} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "AC.L2-3.1.10",
                    "Session lock after inactivity",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session settings manually.",
                )
            )

        # -- AC.L2-3.1.11: Session termination (session lifetime check) ----
        if sessions:
            for s in sessions:
                lifetime = s.get("lifetime_minutes")
                if lifetime is not None and lifetime > 480:
                    findings.append(
                        _finding(
                            "AC.L2-3.1.11",
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
                            "AC.L2-3.1.11",
                            "Session lifetime acceptable",
                            "medium",
                            "pass",
                            f"Session lifetime is {lifetime} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "AC.L2-3.1.11",
                    "Session termination",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session lifetime manually.",
                )
            )

        # -- AC.L2-3.1.5: Least privilege (admin group ratio) -------------
        total_groups = len(data.groups)
        admin_count = len(admin_groups)
        if total_groups > 0 and admin_count > 0:
            ratio = admin_count / total_groups
            if ratio > 0.3:
                findings.append(
                    _finding(
                        "AC.L2-3.1.5",
                        "High proportion of admin groups",
                        "medium",
                        "fail",
                        f"{admin_count}/{total_groups} groups ({ratio:.0%}) are admin groups; "
                        "review least-privilege assignment.",
                        admin_groups=admin_count,
                        total_groups=total_groups,
                        ratio=round(ratio, 2),
                    )
                )
            else:
                findings.append(
                    _finding(
                        "AC.L2-3.1.5",
                        "Admin group ratio appears appropriate",
                        "medium",
                        "pass",
                        f"{admin_count}/{total_groups} groups are admin groups ({ratio:.0%}).",
                    )
                )
        elif total_groups > 0:
            findings.append(
                _finding(
                    "AC.L2-3.1.5",
                    "No admin groups detected",
                    "medium",
                    "pass",
                    f"{total_groups} group(s) exist with no admin-named groups.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AC.L2-3.1.5",
                    "Least privilege assessment",
                    "medium",
                    "manual",
                    "No groups found; unable to assess admin group ratio.",
                )
            )

        # -- IA.L2-3.5.3: MFA for all access (most critical) --------------
        mfa_ok = is_mfa_enforced(data)
        if mfa_ok:
            findings.append(
                _finding(
                    "IA.L2-3.5.3",
                    "MFA enforced for all access",
                    "critical",
                    "pass",
                    "Access policies indicate MFA is enforced.",
                )
            )
        else:
            findings.append(
                _finding(
                    "IA.L2-3.5.3",
                    "MFA not enforced for all access",
                    "critical",
                    "fail",
                    "No access policy requiring MFA was found. "
                    "This is the most critical CMMC Level 2 requirement.",
                )
            )

        # -- IA.L2-3.5.4: Replay-resistant authentication (FIDO2/WebAuthn) -
        active_keys = {a.key for a in authenticators if a.status == "ACTIVE"}
        replay_resistant = active_keys & _REPLAY_RESISTANT_KEYS
        if replay_resistant:
            findings.append(
                _finding(
                    "IA.L2-3.5.4",
                    "Replay-resistant authenticators configured",
                    "high",
                    "pass",
                    f"Found: {', '.join(sorted(replay_resistant))}.",
                )
            )
        else:
            findings.append(
                _finding(
                    "IA.L2-3.5.4",
                    "No replay-resistant authenticators configured",
                    "high",
                    "fail",
                    "Neither FIDO2 nor WebAuthn authenticators are active.",
                )
            )

        # -- IA.L2-3.5.7: Password complexity (min 12, all complexity) -----
        for pp in pw_policies:
            issues: list[str] = []
            if pp.min_length < 12:
                issues.append(f"min length {pp.min_length} (need 12)")
            if not pp.complexity_met:
                issues.append("not all complexity flags enabled")
            if issues:
                findings.append(
                    _finding(
                        "IA.L2-3.5.7",
                        "Password complexity does not meet CMMC requirements",
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
                        "IA.L2-3.5.7",
                        "Password complexity meets CMMC requirements",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' min length {pp.min_length}, full complexity.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "IA.L2-3.5.7",
                    "Password complexity",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- IA.L2-3.5.8: Password reuse prohibition (history >= 5) --------
        for pp in pw_policies:
            if pp.history_count < 5:
                findings.append(
                    _finding(
                        "IA.L2-3.5.8",
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
                        "IA.L2-3.5.8",
                        "Password history meets CMMC requirement",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' remembers {pp.history_count} passwords.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding(
                    "IA.L2-3.5.8",
                    "Password reuse prohibition",
                    "medium",
                    "manual",
                    "No password policies found.",
                )
            )

        # -- IA.L2-3.5.10: Cryptographically protected passwords (FIPS) ----
        domain_lower = data.domain.lower()
        if domain_lower.endswith(".okta.gov") or domain_lower.endswith(".okta.mil"):
            findings.append(
                _finding(
                    "IA.L2-3.5.10",
                    "FIPS-compliant domain detected",
                    "high",
                    "pass",
                    f"Domain '{data.domain}' uses a FedRAMP-authorized cell with "
                    "FIPS 140-2 validated cryptography.",
                )
            )
        else:
            findings.append(
                _finding(
                    "IA.L2-3.5.10",
                    "Non-FIPS domain in use",
                    "high",
                    "fail",
                    f"Domain '{data.domain}' is not an .okta.gov/.okta.mil cell. "
                    "FIPS 140-2 validated password storage may not be guaranteed.",
                )
            )

        # -- AU.L2-3.3.1: Audit records (system logs exist) ---------------
        if data.system_logs:
            findings.append(
                _finding(
                    "AU.L2-3.3.1",
                    "System audit records present",
                    "medium",
                    "pass",
                    f"{len(data.system_logs)} recent system log event(s) found.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AU.L2-3.3.1",
                    "No system audit records found",
                    "medium",
                    "fail",
                    "System log returned no events; verify audit logging is enabled.",
                )
            )

        # -- AU.L2-3.3.4: Alert on audit failure (event hooks/log streams) -
        hooks_or_streams = bool(monitoring.active_event_hooks or monitoring.active_log_streams)
        if hooks_or_streams:
            findings.append(
                _finding(
                    "AU.L2-3.3.4",
                    "Audit alerting capability configured",
                    "medium",
                    "pass",
                    f"{len(monitoring.active_event_hooks)} event hook(s) and "
                    f"{len(monitoring.active_log_streams)} log stream(s) active.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AU.L2-3.3.4",
                    "No audit alerting configured",
                    "medium",
                    "fail",
                    "No active event hooks or log streams; "
                    "audit failure alerting cannot be verified.",
                )
            )

        # -- AU.L2-3.3.5: Correlate audit processes (log streams for SIEM) -
        if monitoring.active_log_streams:
            findings.append(
                _finding(
                    "AU.L2-3.3.5",
                    "Log streams configured for SIEM correlation",
                    "medium",
                    "pass",
                    f"{len(monitoring.active_log_streams)} active log stream(s) "
                    "enable external SIEM correlation.",
                )
            )
        else:
            findings.append(
                _finding(
                    "AU.L2-3.3.5",
                    "No log streams for SIEM correlation",
                    "medium",
                    "fail",
                    "No active log streams; audit process correlation via SIEM is not possible.",
                )
            )

        return findings
