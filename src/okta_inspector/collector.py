"""Okta data collector — Phase 1: retrieve all raw data into OktaData."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from okta_inspector.client import OktaClient
from okta_inspector.models import OktaData

logger = logging.getLogger(__name__)


class OktaDataCollector:
    """Queries 40+ Okta API endpoints and populates an :class:`OktaData` object."""

    def __init__(self, client: OktaClient) -> None:
        self._client = client

    def collect(self) -> OktaData:
        """Run all data retrieval and return a populated OktaData."""
        data = OktaData(domain=self._client.domain)

        self._collect_policies(data)
        self._collect_authentication(data)
        self._collect_users_groups(data)
        self._collect_applications(data)
        self._collect_idps(data)
        self._collect_network_security(data)
        self._collect_monitoring(data)
        self._collect_additional(data)

        return data

    # ------------------------------------------------------------------
    # Section collectors
    # ------------------------------------------------------------------

    def _collect_policies(self, data: OktaData) -> None:
        logger.info("Retrieving all policy types...")
        policy_map: list[tuple[str, str]] = [
            ("OKTA_SIGN_ON", "sign_on_policies"),
            ("PASSWORD", "password_policies"),
            ("MFA_ENROLL", "mfa_enrollment_policies"),
            ("ACCESS_POLICY", "access_policies"),
            ("USER_LIFECYCLE", "user_lifecycle_policies"),
        ]
        for policy_type, attr in policy_map:
            result = self._client.get(f"/policies?type={policy_type}")
            if result and isinstance(result, list):
                setattr(data, attr, result)

                # Fetch password policy rules
                if policy_type == "PASSWORD":
                    for policy in result:
                        pid = policy.get("id")
                        if pid:
                            rules = self._client.get(f"/policies/{pid}/rules")
                            if rules and isinstance(rules, list):
                                data.password_policy_rules[pid] = rules

    def _collect_authentication(self, data: OktaData) -> None:
        logger.info("Retrieving authentication configuration...")
        mapping: list[tuple[str, str]] = [
            ("/authenticators", "authenticators"),
            ("/authorizationServers", "authorization_servers"),
            ("/authorizationServers/default", "default_auth_server"),
            ("/authorizationServers/default/credentials/keys", "auth_server_keys"),
            ("/authorizationServers/default/claims", "auth_claims"),
        ]
        for endpoint, attr in mapping:
            result = self._client.get(endpoint)
            if result is not None:
                setattr(data, attr, result)

    def _collect_users_groups(self, data: OktaData) -> None:
        logger.info("Retrieving users and groups...")
        users = self._client.get("/users", params={"limit": self._client.page_size})
        if users and isinstance(users, list):
            data.users = users

        groups = self._client.get("/groups", params={"limit": self._client.page_size})
        if groups and isinstance(groups, list):
            data.groups = groups

    def _collect_applications(self, data: OktaData) -> None:
        logger.info("Retrieving applications...")
        apps = self._client.get("/apps", params={"limit": self._client.page_size})
        if apps and isinstance(apps, list):
            data.apps = apps

    def _collect_idps(self, data: OktaData) -> None:
        logger.info("Retrieving identity providers...")
        idps = self._client.get("/idps")
        if idps and isinstance(idps, list):
            data.idps = idps

    def _collect_network_security(self, data: OktaData) -> None:
        logger.info("Retrieving network and security settings...")
        mapping: list[tuple[str, str]] = [
            ("/zones", "network_zones"),
            ("/threats/configuration", "threat_insight"),
            ("/trustedOrigins", "trusted_origins"),
            ("/domains", "custom_domains"),
        ]
        for endpoint, attr in mapping:
            result = self._client.get(endpoint)
            if result is not None:
                setattr(data, attr, result)

    def _collect_monitoring(self, data: OktaData) -> None:
        logger.info("Retrieving monitoring configuration...")
        for endpoint, attr in [("/eventHooks", "event_hooks"), ("/logStreams", "log_streams")]:
            result = self._client.get(endpoint)
            setattr(data, attr, result if result and isinstance(result, list) else [])

        # Recent system logs (last 24 h, limited pages)
        logger.info("Retrieving recent system logs...")
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs = self._client.get("/logs", params={"since": since, "limit": self._client.page_size}, max_pages=3)
        data.system_logs = logs if logs and isinstance(logs, list) else []

    def _collect_additional(self, data: OktaData) -> None:
        logger.info("Retrieving additional settings...")
        simple: list[tuple[str, str, Any]] = [
            ("/org/factors", "org_factors", {}),
            ("/brands", "brands", []),
            ("/templates/email", "email_templates", []),
            ("/behaviors", "behaviors", []),
            ("/workflows", "workflows", []),
            ("/meta/schemas/user/default", "user_schema", {}),
        ]
        for endpoint, attr, default in simple:
            result = self._client.get(endpoint)
            setattr(data, attr, result if result is not None else default)
