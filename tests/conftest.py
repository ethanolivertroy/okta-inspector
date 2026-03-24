"""Shared test fixtures — mock OktaData for analyzer and reporter tests."""

from __future__ import annotations

import pytest

from okta_inspector.models import OktaData


@pytest.fixture
def minimal_okta_data() -> OktaData:
    """Bare-minimum OktaData for smoke tests."""
    return OktaData(domain="test.okta.com")


@pytest.fixture
def sample_okta_data() -> OktaData:
    """Realistic OktaData with representative test data."""
    return OktaData(
        domain="acme-corp.okta.com",
        sign_on_policies=[
            {
                "id": "policy1",
                "name": "Default Sign-On Policy",
                "priority": 1,
            }
        ],
        password_policies=[
            {
                "id": "pw1",
                "name": "Default Password Policy",
                "settings": {
                    "password": {
                        "complexity": {
                            "minLength": 12,
                            "useUpperCase": True,
                            "useLowerCase": True,
                            "useNumber": True,
                            "useSymbol": False,
                            "excludeUsername": True,
                        },
                        "age": {
                            "minAgeMinutes": 60,
                            "maxAgeDays": 90,
                            "expireWarnDays": 7,
                            "historyCount": 4,
                        },
                        "lockout": {
                            "maxAttempts": 5,
                            "autoUnlockMinutes": 30,
                        },
                    }
                },
            }
        ],
        mfa_enrollment_policies=[
            {"id": "mfa1", "name": "MFA Enrollment", "type": "MFA_ENROLL"}
        ],
        access_policies=[
            {"id": "ap1", "name": "Okta Admin Console", "type": "ACCESS_POLICY"},
            {"id": "ap2", "name": "Okta Dashboard", "type": "ACCESS_POLICY"},
        ],
        user_lifecycle_policies=[
            {"id": "lc1", "name": "Default Lifecycle", "type": "USER_LIFECYCLE"}
        ],
        authenticators=[
            {"key": "okta_password", "name": "Password", "type": "password", "status": "ACTIVE", "provider": {}, "settings": {}},
            {"key": "okta_verify", "name": "Okta Verify", "type": "app", "status": "ACTIVE", "provider": {}, "settings": {}},
        ],
        users=[
            {"id": "u1", "status": "ACTIVE", "lastLogin": "2026-03-20T10:00:00Z", "profile": {"login": "user1@acme.com"}},
            {"id": "u2", "status": "ACTIVE", "lastLogin": "2025-10-01T10:00:00Z", "profile": {"login": "olduser@acme.com"}},
            {"id": "u3", "status": "SUSPENDED", "lastLogin": None, "profile": {"login": "suspended@acme.com"}},
        ],
        groups=[
            {"id": "g1", "profile": {"name": "Everyone"}},
            {"id": "g2", "profile": {"name": "Admins"}},
            {"id": "g3", "profile": {"name": "Developers"}},
        ],
        apps=[
            {"id": "app1", "name": "Slack", "status": "ACTIVE"},
            {"id": "app2", "name": "AWS Console", "status": "ACTIVE"},
        ],
        idps=[],
        network_zones=[
            {"id": "nz1", "name": "Corporate", "type": "IP"}
        ],
        trusted_origins=[
            {"id": "to1", "name": "https://app.acme.com", "origin": "https://app.acme.com"}
        ],
        event_hooks=[],
        log_streams=[
            {"id": "ls1", "name": "Splunk Stream", "status": "ACTIVE", "type": "aws_eventbridge"}
        ],
        system_logs=[
            {"eventType": "user.session.start", "actor": {"id": "u1"}},
            {"eventType": "user.session.start", "actor": {"id": "u2"}},
            {"eventType": "user.authentication.sso", "actor": {"id": "u1"}},
        ],
        behaviors=[
            {"id": "b1", "name": "New Device", "type": "ANOMALOUS_DEVICE"}
        ],
    )
