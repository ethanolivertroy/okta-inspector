"""Tests for shared analysis functions in analyzers/common.py."""

from okta_inspector.analyzers.common import (
    analyze_certificates,
    analyze_monitoring,
    analyze_password_policies,
    analyze_users,
    find_admin_groups,
    has_admin_console_mfa,
    has_dashboard_mfa,
)
from okta_inspector.models import OktaData


def test_analyze_password_policies(sample_okta_data: OktaData):
    results = analyze_password_policies(sample_okta_data)
    assert len(results) == 1
    pp = results[0]
    assert pp.min_length == 12
    assert pp.require_uppercase is True
    assert pp.require_symbol is False
    assert pp.complexity_met is False  # symbol is False
    assert pp.max_attempts == 5
    assert pp.history_count == 4


def test_analyze_users(sample_okta_data: OktaData):
    result = analyze_users(sample_okta_data)
    assert result.total_users == 3
    assert result.active_users == 2
    # u2 has lastLogin in Oct 2025, >90 days ago from March 2026
    assert len(result.inactive_users) >= 1


def test_analyze_certificates_empty(sample_okta_data: OktaData):
    result = analyze_certificates(sample_okta_data)
    assert result.has_piv_cac is False


def test_analyze_monitoring(sample_okta_data: OktaData):
    result = analyze_monitoring(sample_okta_data)
    assert len(result.active_log_streams) == 1
    assert len(result.active_event_hooks) == 0
    assert len(result.log_event_summary) > 0


def test_has_admin_console_mfa(sample_okta_data: OktaData):
    assert has_admin_console_mfa(sample_okta_data) is True


def test_has_dashboard_mfa(sample_okta_data: OktaData):
    assert has_dashboard_mfa(sample_okta_data) is True


def test_find_admin_groups(sample_okta_data: OktaData):
    admins = find_admin_groups(sample_okta_data)
    assert len(admins) == 1
    assert admins[0]["profile"]["name"] == "Admins"
