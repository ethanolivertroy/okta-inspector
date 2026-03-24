"""SOC 2 framework analyzer."""

from __future__ import annotations

from okta_inspector.analyzers import register_analyzer
from okta_inspector.analyzers.base import FrameworkAnalyzer
from okta_inspector.analyzers.common import (
    analyze_users,
    is_mfa_enforced,
)
from okta_inspector.models import ComplianceFinding, OktaData

_FRAMEWORK = "SOC2"

_ROLE_KEYWORDS = {"admin", "administrator", "manager", "owner", "editor", "viewer", "readonly", "read-only"}


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
class SOC2Analyzer(FrameworkAnalyzer):
    name = "soc2"
    display_name = "SOC 2"

    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        findings: list[ComplianceFinding] = []

        user_analysis = analyze_users(data)
        sessions = _extract_session_settings(data)

        # -- CC6.1: Logical access with MFA --------------------------------
        mfa_ok = is_mfa_enforced(data)
        if mfa_ok:
            findings.append(
                _finding(
                    "CC6.1",
                    "Logical access controls with MFA",
                    "high",
                    "pass",
                    "Access policies indicate MFA is enforced for logical access.",
                )
            )
        else:
            findings.append(
                _finding(
                    "CC6.1",
                    "MFA not enforced for logical access",
                    "high",
                    "fail",
                    "No access policy requiring MFA was found; logical access may be weakly protected.",
                )
            )

        # -- CC6.2: User lifecycle management ------------------------------
        inactive_count = len(user_analysis.inactive_users)
        deprovisioned = user_analysis.users_by_status.get("DEPROVISIONED", [])
        suspended = user_analysis.users_by_status.get("SUSPENDED", [])

        if inactive_count == 0:
            findings.append(
                _finding(
                    "CC6.2",
                    "User lifecycle management effective",
                    "medium",
                    "pass",
                    "No users inactive for 90+ days; lifecycle management appears effective.",
                    deprovisioned_count=len(deprovisioned),
                    suspended_count=len(suspended),
                )
            )
        else:
            findings.append(
                _finding(
                    "CC6.2",
                    "Inactive users indicate lifecycle management gaps",
                    "medium",
                    "fail",
                    f"{inactive_count} user(s) inactive for 90+ days; "
                    "review user de-provisioning process.",
                    inactive_count=inactive_count,
                    deprovisioned_count=len(deprovisioned),
                    suspended_count=len(suspended),
                )
            )

        # -- CC6.3: Role-based access (groups with role keywords) ----------
        role_groups = [
            g
            for g in data.groups
            if any(
                kw in g.get("profile", {}).get("name", "").lower()
                for kw in _ROLE_KEYWORDS
            )
        ]
        if role_groups:
            names = [g.get("profile", {}).get("name", "") for g in role_groups[:10]]
            findings.append(
                _finding(
                    "CC6.3",
                    "Role-based access groups configured",
                    "medium",
                    "pass",
                    f"{len(role_groups)} group(s) with role-based naming detected.",
                    sample_groups=names,
                )
            )
        elif data.groups:
            findings.append(
                _finding(
                    "CC6.3",
                    "No role-based groups detected",
                    "medium",
                    "manual",
                    f"{len(data.groups)} group(s) exist but none match common role-based naming "
                    "conventions; verify RBAC implementation.",
                )
            )
        else:
            findings.append(
                _finding(
                    "CC6.3",
                    "No groups configured",
                    "medium",
                    "fail",
                    "No groups found; role-based access cannot be verified.",
                )
            )

        # -- CC6.6: Session timeout <= 30 min ------------------------------
        if sessions:
            for s in sessions:
                idle = s.get("idle_minutes")
                if idle is not None and idle > 30:
                    findings.append(
                        _finding(
                            "CC6.6",
                            "Session timeout exceeds 30 minutes",
                            "medium",
                            "fail",
                            f"Policy '{s['policy_name']}' rule '{s['rule_name']}' "
                            f"idle timeout is {idle} min (max 30 for SOC 2).",
                            idle_timeout_minutes=idle,
                        )
                    )
                elif idle is not None:
                    findings.append(
                        _finding(
                            "CC6.6",
                            "Session timeout within SOC 2 limit",
                            "medium",
                            "pass",
                            f"Idle timeout is {idle} min.",
                        )
                    )
        else:
            findings.append(
                _finding(
                    "CC6.6",
                    "Session timeout",
                    "medium",
                    "manual",
                    "No embedded session rules found; verify session timeout settings.",
                )
            )

        # -- CC6.7: Trusted origins configured -----------------------------
        if data.trusted_origins:
            findings.append(
                _finding(
                    "CC6.7",
                    "Trusted origins configured",
                    "low",
                    "pass",
                    f"{len(data.trusted_origins)} trusted origin(s) configured.",
                )
            )
        else:
            findings.append(
                _finding(
                    "CC6.7",
                    "No trusted origins configured",
                    "low",
                    "fail",
                    "No trusted origins found; cross-origin access may be unrestricted.",
                )
            )

        # -- CC6.8: Network zones + behaviors configured -------------------
        zones_configured = bool(data.network_zones)
        behaviors_configured = bool(data.behaviors)
        if zones_configured and behaviors_configured:
            findings.append(
                _finding(
                    "CC6.8",
                    "Network zones and behaviors configured",
                    "medium",
                    "pass",
                    f"{len(data.network_zones)} network zone(s) and "
                    f"{len(data.behaviors)} behavior rule(s) configured.",
                )
            )
        elif zones_configured or behaviors_configured:
            findings.append(
                _finding(
                    "CC6.8",
                    "Partial network security configuration",
                    "medium",
                    "manual",
                    f"Network zones: {len(data.network_zones)}, "
                    f"behaviors: {len(data.behaviors)}. "
                    "Both are recommended for SOC 2 boundary protection.",
                )
            )
        else:
            findings.append(
                _finding(
                    "CC6.8",
                    "No network zones or behaviors configured",
                    "medium",
                    "fail",
                    "Neither network zones nor behavior rules are configured.",
                )
            )

        return findings
