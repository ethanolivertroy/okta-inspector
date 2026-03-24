"""Data models for okta-inspector."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class ComplianceFinding:
    """A single compliance finding from a framework analyzer."""

    framework: str
    control_id: str
    title: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    status: str  # "pass" | "fail" | "manual" | "not_applicable" | "error"
    comments: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OktaData:
    """Container for all collected Okta API data.

    Populated by OktaDataCollector and passed to every analyzer.
    Analyzers must never read from disk — this object IS the data bus.
    """

    domain: str

    # Policies (keyed by type)
    sign_on_policies: list[dict[str, Any]] = field(default_factory=list)
    password_policies: list[dict[str, Any]] = field(default_factory=list)
    mfa_enrollment_policies: list[dict[str, Any]] = field(default_factory=list)
    access_policies: list[dict[str, Any]] = field(default_factory=list)
    user_lifecycle_policies: list[dict[str, Any]] = field(default_factory=list)

    # Password policy rules (keyed by policy ID)
    password_policy_rules: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    # Authentication
    authenticators: list[dict[str, Any]] = field(default_factory=list)
    authorization_servers: list[dict[str, Any]] = field(default_factory=list)
    default_auth_server: dict[str, Any] = field(default_factory=dict)
    auth_server_keys: list[dict[str, Any]] = field(default_factory=list)
    auth_claims: list[dict[str, Any]] = field(default_factory=list)

    # Users & Groups
    users: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)

    # Applications
    apps: list[dict[str, Any]] = field(default_factory=list)

    # Identity Providers
    idps: list[dict[str, Any]] = field(default_factory=list)

    # Network & Security
    network_zones: list[dict[str, Any]] = field(default_factory=list)
    threat_insight: dict[str, Any] = field(default_factory=dict)
    trusted_origins: list[dict[str, Any]] = field(default_factory=list)
    custom_domains: list[dict[str, Any]] = field(default_factory=list)

    # Monitoring
    event_hooks: list[dict[str, Any]] = field(default_factory=list)
    log_streams: list[dict[str, Any]] = field(default_factory=list)
    system_logs: list[dict[str, Any]] = field(default_factory=list)

    # Additional
    org_factors: list[dict[str, Any]] | dict[str, Any] = field(default_factory=dict)
    brands: list[dict[str, Any]] = field(default_factory=list)
    email_templates: list[dict[str, Any]] = field(default_factory=list)
    behaviors: list[dict[str, Any]] = field(default_factory=list)
    workflows: list[dict[str, Any]] = field(default_factory=list)
    user_schema: dict[str, Any] = field(default_factory=dict)


# ---------- Intermediate analysis types used by common.py ----------


@dataclass
class SessionAnalysis:
    """Structured result from session management analysis."""

    policy_id: str
    policy_name: str
    priority: int | None
    rules: list[SessionRuleAnalysis] = field(default_factory=list)


@dataclass
class SessionRuleAnalysis:
    """A single session rule's key settings."""

    name: str
    idle_timeout_minutes: int | None
    lifetime_minutes: int | None
    persistent_cookies: bool | None


@dataclass
class PasswordPolicyAnalysis:
    """Structured result from password policy analysis."""

    policy_id: str
    policy_name: str
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_number: bool
    require_symbol: bool
    exclude_username: bool
    min_age_minutes: int
    max_age_days: int
    history_count: int
    max_attempts: int
    lockout_duration_minutes: int

    @property
    def complexity_met(self) -> bool:
        return (
            self.require_uppercase
            and self.require_lowercase
            and self.require_number
            and self.require_symbol
        )


@dataclass
class AuthenticatorInfo:
    """Structured authenticator data."""

    key: str
    name: str
    type: str
    status: str
    provider: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)


@dataclass
class MonitoringAnalysis:
    """Structured result from monitoring analysis."""

    active_event_hooks: list[dict[str, Any]] = field(default_factory=list)
    active_log_streams: list[dict[str, Any]] = field(default_factory=list)
    log_event_summary: list[dict[str, str | int]] = field(default_factory=list)


@dataclass
class UserAnalysis:
    """Structured result from user management analysis."""

    total_users: int = 0
    active_users: int = 0
    inactive_users: list[dict[str, Any]] = field(default_factory=list)
    users_by_status: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class CertificateAnalysis:
    """Structured result from certificate/PIV/CAC analysis."""

    cert_idps: list[dict[str, Any]] = field(default_factory=list)
    cert_authenticators: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_piv_cac(self) -> bool:
        return bool(self.cert_idps or self.cert_authenticators)


@dataclass
class AuditResult:
    """Final result of a complete audit run."""

    findings: list[ComplianceFinding]
    data: OktaData
    api_call_count: int
    timestamp: str
    domain: str
