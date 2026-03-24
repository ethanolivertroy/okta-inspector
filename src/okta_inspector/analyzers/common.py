"""Shared analysis functions used by multiple framework analyzers.

Each function takes an :class:`OktaData` and returns a typed intermediate
dataclass.  Framework analyzers call these, then apply their own thresholds.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from okta_inspector.models import (
    AuthenticatorInfo,
    CertificateAnalysis,
    MonitoringAnalysis,
    OktaData,
    PasswordPolicyAnalysis,
    SessionAnalysis,
    SessionRuleAnalysis,
    UserAnalysis,
)

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Session management
# ------------------------------------------------------------------


def analyze_sessions(data: OktaData) -> list[SessionAnalysis]:
    """Analyze sign-on policies for session settings."""
    results: list[SessionAnalysis] = []
    for policy in data.sign_on_policies:
        sa = SessionAnalysis(
            policy_id=policy.get("id", ""),
            policy_name=policy.get("name", ""),
            priority=policy.get("priority"),
        )
        # Rules may be embedded or fetched separately — not available from
        # the sign-on policy endpoint in the current collector, so we skip
        # rule-level detail here.  Framework analyzers that need rule data
        # should check access_policies (which include inline rules).
        results.append(sa)
    return results


# ------------------------------------------------------------------
# Password policies
# ------------------------------------------------------------------


def analyze_password_policies(data: OktaData) -> list[PasswordPolicyAnalysis]:
    """Extract structured password policy data."""
    results: list[PasswordPolicyAnalysis] = []
    for policy in data.password_policies:
        settings = policy.get("settings", {}).get("password", {})
        complexity = settings.get("complexity", {})
        age = settings.get("age", {})
        lockout = settings.get("lockout", {})

        results.append(
            PasswordPolicyAnalysis(
                policy_id=policy.get("id", ""),
                policy_name=policy.get("name", ""),
                min_length=complexity.get("minLength", 0),
                require_uppercase=complexity.get("useUpperCase", False),
                require_lowercase=complexity.get("useLowerCase", False),
                require_number=complexity.get("useNumber", False),
                require_symbol=complexity.get("useSymbol", False),
                exclude_username=complexity.get("excludeUsername", False),
                min_age_minutes=age.get("minAgeMinutes", 0),
                max_age_days=age.get("maxAgeDays", 0),
                history_count=age.get("historyCount", 0),
                max_attempts=lockout.get("maxAttempts", 999),
                lockout_duration_minutes=lockout.get("autoUnlockMinutes", 0),
            )
        )
    return results


# ------------------------------------------------------------------
# Authenticators
# ------------------------------------------------------------------


def analyze_authenticators(data: OktaData) -> list[AuthenticatorInfo]:
    """Extract structured authenticator data."""
    return [
        AuthenticatorInfo(
            key=auth.get("key", ""),
            name=auth.get("name", ""),
            type=auth.get("type", ""),
            status=auth.get("status", ""),
            provider=auth.get("provider", {}),
            settings=auth.get("settings", {}),
        )
        for auth in data.authenticators
    ]


# ------------------------------------------------------------------
# MFA enforcement check
# ------------------------------------------------------------------


def is_mfa_enforced(data: OktaData) -> bool:
    """Return True if any access policy appears to require MFA."""
    for policy in data.access_policies:
        name = policy.get("name", "")
        if "Admin Console" in name or "Dashboard" in name:
            return True
    return False


def has_admin_console_mfa(data: OktaData) -> bool:
    return any("Admin Console" in p.get("name", "") for p in data.access_policies)


def has_dashboard_mfa(data: OktaData) -> bool:
    return any("Dashboard" in p.get("name", "") for p in data.access_policies)


# ------------------------------------------------------------------
# User management
# ------------------------------------------------------------------


def analyze_users(data: OktaData) -> UserAnalysis:
    """Analyze user accounts for status and inactivity."""
    result = UserAnalysis(total_users=len(data.users))

    statuses = ["ACTIVE", "LOCKED_OUT", "PASSWORD_EXPIRED", "RECOVERY", "SUSPENDED", "DEPROVISIONED"]
    for status in statuses:
        result.users_by_status[status] = [u for u in data.users if u.get("status") == status]

    result.active_users = len(result.users_by_status.get("ACTIVE", []))

    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    for user in data.users:
        last_login = user.get("lastLogin")
        if last_login:
            try:
                dt = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
                if dt < cutoff:
                    result.inactive_users.append(user)
            except (ValueError, TypeError):
                pass

    return result


# ------------------------------------------------------------------
# Certificates / PIV / CAC
# ------------------------------------------------------------------


def analyze_certificates(data: OktaData) -> CertificateAnalysis:
    """Check for PIV/CAC and certificate-based authentication."""
    keywords = {"smart card", "piv", "cac", "certificate"}

    cert_idps = [
        idp
        for idp in data.idps
        if idp.get("type") in ("X509", "SMARTCARD")
        or any(kw in idp.get("name", "").lower() for kw in keywords)
    ]
    cert_authenticators = [
        auth
        for auth in data.authenticators
        if auth.get("type") in ("cert", "x509")
        or any(kw in auth.get("key", "").lower() for kw in {"smart_card", "certificate", "piv"})
    ]
    return CertificateAnalysis(cert_idps=cert_idps, cert_authenticators=cert_authenticators)


# ------------------------------------------------------------------
# Monitoring
# ------------------------------------------------------------------


def analyze_monitoring(data: OktaData) -> MonitoringAnalysis:
    """Summarize event hooks, log streams, and recent log events."""
    active_hooks = [h for h in data.event_hooks if h.get("status") == "ACTIVE"]
    active_streams = [s for s in data.log_streams if s.get("status") == "ACTIVE"]

    event_summary: dict[str, int] = {}
    for log in data.system_logs:
        et = log.get("eventType", "Unknown")
        event_summary[et] = event_summary.get(et, 0) + 1

    summary_list = [
        {"eventType": k, "count": v}
        for k, v in sorted(event_summary.items(), key=lambda x: x[1], reverse=True)
    ]

    return MonitoringAnalysis(
        active_event_hooks=active_hooks,
        active_log_streams=active_streams,
        log_event_summary=summary_list,
    )


# ------------------------------------------------------------------
# Admin groups
# ------------------------------------------------------------------


def find_admin_groups(data: OktaData) -> list[dict]:
    """Return groups whose name contains 'admin' or 'administrator'."""
    return [
        g
        for g in data.groups
        if "admin" in g.get("profile", {}).get("name", "").lower()
        or "administrator" in g.get("profile", {}).get("name", "").lower()
    ]
