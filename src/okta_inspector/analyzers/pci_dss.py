"""PCI-DSS 4.0.1 framework analyzer."""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_authenticators,
    analyze_password_policies,
    is_mfa_enforced,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "PCI-DSS"

_STRONG_AUTH_KEYS = {"okta_verify", "webauthn", "fido2", "smart_card_idp"}


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
class PCIDSSAnalyzer(FrameworkAnalyzer):
    name = "pci_dss"
    display_name = "PCI-DSS 4.0.1"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        pw_policies = analyze_password_policies(data)
        authenticators = analyze_authenticators(data)
        sessions = _extract_session_settings(data)

        # -- 7.2.1: RBAC (groups exist) ------------------------------------
        if data.groups:
            findings.append(
                _finding(
                    "7.2.1",
                    "Role-based access control groups configured",
                    "medium",
                    "pass",
                    f"{len(data.groups)} group(s) configured for access control.",
                )
            )
        else:
            findings.append(
                _finding(
                    "7.2.1",
                    "No access control groups configured",
                    "medium",
                    "fail",
                    "No groups found; RBAC cannot be verified.",
                )
            )

        # -- 8.2.1: Strong authentication methods --------------------------
        active_keys = {a.key for a in authenticators if a.status == "ACTIVE"}
        strong_found = active_keys & _STRONG_AUTH_KEYS
        if strong_found:
            findings.append(
                _finding(
                    "8.2.1",
                    "Strong authentication methods configured",
                    "high",
                    "pass",
                    f"Strong authenticators found: {', '.join(sorted(strong_found))}.",
                )
            )
        else:
            findings.append(
                _finding(
                    "8.2.1",
                    "No strong authentication methods configured",
                    "high",
                    "fail",
                    "None of okta_verify, webauthn, fido2, or smart_card_idp are active.",
                )
            )

        # -- 8.2.6: Lockout <= 6 attempts ----------------------------------
        for pp in pw_policies:
            if pp.max_attempts > 6:
                findings.append(
                    _finding(
                        "8.2.6",
                        "Lockout threshold exceeds 6 attempts",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' allows {pp.max_attempts} attempts (max 6).",
                        max_attempts=pp.max_attempts,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "8.2.6",
                        "Lockout threshold within PCI-DSS limit",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' locks after {pp.max_attempts} attempts.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("8.2.6", "Account lockout", "medium", "manual", "No password policies found.")
            )

        # -- 8.2.8: Session idle timeout <= 15 min -------------------------
        if sessions:
            for s in sessions:
                idle = s.get("idle_minutes")
                if idle is not None and idle > 15:
                    findings.append(
                        _finding(
                            "8.2.8",
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
                            "8.2.8",
                            "Session idle timeout within PCI-DSS limit",
                            "medium",
                            "pass",
                            f"Idle timeout is {idle} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "8.2.8",
                    "Session idle timeout",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session timeout settings.",
                )
            )

        # -- 8.3.1: MFA enforced -------------------------------------------
        mfa_ok = is_mfa_enforced(data)
        if mfa_ok:
            findings.append(
                _finding(
                    "8.3.1",
                    "MFA enforced",
                    "high",
                    "pass",
                    "Access policies indicate MFA is enforced.",
                )
            )
        else:
            findings.append(
                _finding(
                    "8.3.1",
                    "MFA not enforced",
                    "high",
                    "fail",
                    "No access policy requiring MFA was found.",
                )
            )

        # -- 8.3.6: Password min 12 + complexity ---------------------------
        for pp in pw_policies:
            issues: list[str] = []
            if pp.min_length < 12:
                issues.append(f"min length {pp.min_length} (need 12)")
            if not pp.complexity_met:
                issues.append("not all complexity flags enabled")
            if issues:
                findings.append(
                    _finding(
                        "8.3.6",
                        "Password policy does not meet PCI-DSS requirements",
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
                        "8.3.6",
                        "Password policy meets PCI-DSS requirements",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' min length {pp.min_length}, full complexity.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("8.3.6", "Password complexity", "medium", "manual", "No password policies found.")
            )

        # -- 8.3.9: Password max age <= 90 days ----------------------------
        for pp in pw_policies:
            if pp.max_age_days == 0:
                findings.append(
                    _finding(
                        "8.3.9",
                        "Password expiration not configured",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' has no max age (0 days). "
                        "PCI-DSS requires rotation at most every 90 days.",
                        max_age_days=pp.max_age_days,
                    )
                )
            elif pp.max_age_days > 90:
                findings.append(
                    _finding(
                        "8.3.9",
                        "Password max age exceeds 90 days",
                        "medium",
                        "fail",
                        f"Policy '{pp.policy_name}' max age is {pp.max_age_days} days (max 90).",
                        max_age_days=pp.max_age_days,
                    )
                )
            else:
                findings.append(
                    _finding(
                        "8.3.9",
                        "Password max age within PCI-DSS limit",
                        "medium",
                        "pass",
                        f"Policy '{pp.policy_name}' max age is {pp.max_age_days} days.",
                    )
                )
        if not pw_policies:
            findings.append(
                _finding("8.3.9", "Password max age", "medium", "manual", "No password policies found.")
            )

        return findings
