"""Tests for data models."""

from okta_inspector.models import (
    ComplianceFinding,
    OktaData,
    PasswordPolicyAnalysis,
    CertificateAnalysis,
)


def test_compliance_finding_to_dict():
    f = ComplianceFinding(
        framework="STIG",
        control_id="V-273186",
        title="Session timeout",
        severity="medium",
        status="fail",
        comments="Too long",
        details={"timeout": 30},
    )
    d = f.to_dict()
    assert d["framework"] == "STIG"
    assert d["details"]["timeout"] == 30


def test_okta_data_defaults():
    data = OktaData(domain="test.okta.com")
    assert data.users == []
    assert data.password_policy_rules == {}
    assert data.domain == "test.okta.com"


def test_password_policy_complexity():
    pp = PasswordPolicyAnalysis(
        policy_id="pw1",
        policy_name="Default",
        min_length=15,
        require_uppercase=True,
        require_lowercase=True,
        require_number=True,
        require_symbol=True,
        exclude_username=True,
        min_age_minutes=60,
        max_age_days=60,
        history_count=5,
        max_attempts=3,
        lockout_duration_minutes=30,
    )
    assert pp.complexity_met is True

    pp.require_symbol = False
    assert pp.complexity_met is False


def test_certificate_analysis_has_piv():
    empty = CertificateAnalysis()
    assert empty.has_piv_cac is False

    with_idp = CertificateAnalysis(cert_idps=[{"type": "X509"}])
    assert with_idp.has_piv_cac is True
