"""Audit engine — orchestrates collect → analyze → report → archive."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime

from okta_inspector.analyzers import get_analyzers
from okta_inspector.client import OktaClient
from okta_inspector.collector import OktaDataCollector
from okta_inspector.models import AuditResult, ComplianceFinding, OktaData
from okta_inspector.output import OutputManager
from okta_inspector.reporters import get_reporters

logger = logging.getLogger(__name__)


class AuditEngine:
    """Top-level orchestrator for an Okta compliance audit."""

    def __init__(
        self,
        client: OktaClient,
        output: OutputManager,
        *,
        frameworks: list[str] | None = None,
    ) -> None:
        self._client = client
        self._output = output
        self._frameworks = frameworks

    def run(self) -> AuditResult:
        """Execute the full 3-phase audit and return the result."""
        # Phase 1: Collect
        logger.info("=== PHASE 1: Core Data Retrieval ===")
        collector = OktaDataCollector(self._client)
        data = collector.collect()
        self._save_raw_data(data)

        # Phase 2: Analyze
        logger.info("=== PHASE 2: Analysis and Filtering ===")
        findings = self._run_analyzers(data)
        self._save_analysis(data, findings)

        # Phase 3: Report
        logger.info("=== PHASE 3: Compliance Reporting ===")
        self._run_reporters(findings, data)

        # Archive
        archive = self._output.create_archive()

        result = AuditResult(
            findings=findings,
            data=data,
            api_call_count=self._client.api_call_count,
            timestamp=datetime.now().isoformat(),
            domain=self._client.domain,
        )

        self._print_summary(result, archive)
        return result

    # ------------------------------------------------------------------
    # Phase helpers
    # ------------------------------------------------------------------

    def _run_analyzers(self, data: OktaData) -> list[ComplianceFinding]:
        analyzers = get_analyzers(self._frameworks)
        all_findings: list[ComplianceFinding] = []
        for analyzer in analyzers:
            logger.info("Running %s analyzer...", analyzer.display_name)
            try:
                findings = analyzer.analyze(data)
                all_findings.extend(findings)
            except Exception as e:
                logger.error("Error in %s analyzer: %s", analyzer.name, e)
        return all_findings

    def _run_reporters(self, findings: list[ComplianceFinding], data: OktaData) -> None:
        reporters = get_reporters()
        for reporter in reporters:
            logger.info("Generating %s report...", reporter.display_name)
            try:
                reporter.generate(findings, data, self._output)
            except Exception as e:
                logger.error("Error in %s reporter: %s", reporter.name, e)

    # ------------------------------------------------------------------
    # Data persistence (raw + analysis JSON for offline review)
    # ------------------------------------------------------------------

    def _save_raw_data(self, data: OktaData) -> None:
        """Persist raw API responses as JSON for auditor review."""
        save = self._output.save_json
        save(data.sign_on_policies, "sign_on_policies.json")
        save(data.password_policies, "password_policies.json")
        save(data.mfa_enrollment_policies, "mfa_enrollment_policies.json")
        save(data.access_policies, "access_policies.json")
        save(data.user_lifecycle_policies, "user_lifecycle_policies.json")
        for pid, rules in data.password_policy_rules.items():
            save(rules, f"password_policy_rules_{pid}.json")
        save(data.authenticators, "authenticators.json")
        save(data.authorization_servers, "authorization_servers.json")
        save(data.default_auth_server, "default_auth_server.json")
        save(data.auth_server_keys, "auth_server_keys.json")
        save(data.auth_claims, "auth_claims.json")
        save(data.users, "all_users.json")
        save(data.groups, "groups.json")
        save(data.apps, "applications.json")
        save(data.idps, "idp_settings.json")
        save(data.network_zones, "network_zones.json")
        save(data.threat_insight, "threat_insight_settings.json")
        save(data.trusted_origins, "trusted_origins.json")
        save(data.custom_domains, "custom_domains.json")
        save(data.event_hooks, "event_hooks.json")
        save(data.log_streams, "log_streams.json")
        save(data.system_logs, "system_logs_recent.json")
        save(data.org_factors, "org_factors.json")
        save(data.brands, "brands.json")
        save(data.email_templates, "email_templates.json")
        save(data.behaviors, "behavior_rules.json")
        save(data.workflows, "workflows.json")
        save(data.user_schema, "user_schema.json")

    def _save_analysis(self, data: OktaData, findings: list[ComplianceFinding]) -> None:
        """Persist analysis-level JSON (derived data + findings)."""
        from okta_inspector.analyzers.common import (
            analyze_authenticators,
            analyze_certificates,
            analyze_monitoring,
            analyze_password_policies,
            analyze_users,
        )

        save = self._output.save_json

        # Shared analysis artifacts
        pw = analyze_password_policies(data)
        save([asdict(p) for p in pw], "password_policy_analysis.json", "analysis")

        users = analyze_users(data)
        save(users.inactive_users, "inactive_users.json", "analysis")
        for status, user_list in users.users_by_status.items():
            save(user_list, f"users_{status}.json", "analysis")

        auths = analyze_authenticators(data)
        save([asdict(a) for a in auths], "authenticator_analysis.json", "analysis")

        certs = analyze_certificates(data)
        save(certs.cert_idps, "certificate_idps.json", "analysis")
        save(certs.cert_authenticators, "certificate_authenticators.json", "analysis")

        monitoring = analyze_monitoring(data)
        save(monitoring.active_event_hooks, "active_event_hooks.json", "analysis")
        save(monitoring.active_log_streams, "active_log_streams.json", "analysis")
        save(monitoring.log_event_summary, "log_event_summary.json", "analysis")

        # All findings as JSON
        save([f.to_dict() for f in findings], "all_findings.json", "analysis")

        # Per-framework summaries
        frameworks = {f.framework for f in findings}
        for fw in frameworks:
            fw_findings = [f for f in findings if f.framework == fw]
            summary = {
                "framework": fw,
                "total": len(fw_findings),
                "passed": len([f for f in fw_findings if f.status == "pass"]),
                "failed": len([f for f in fw_findings if f.status == "fail"]),
                "manual": len([f for f in fw_findings if f.status == "manual"]),
                "findings": [f.to_dict() for f in fw_findings],
            }
            save(summary, f"{fw.lower()}_analysis.json", "analysis")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    @staticmethod
    def _print_summary(result: AuditResult, archive: object) -> None:
        passed = len([f for f in result.findings if f.status == "pass"])
        failed = len([f for f in result.findings if f.status == "fail"])
        manual = len([f for f in result.findings if f.status == "manual"])
        frameworks = {f.framework for f in result.findings}

        print("\n" + "=" * 50)
        print("Okta Security Audit Complete!")
        print("=" * 50)
        print(f"\nDomain:            {result.domain}")
        print(f"API calls:         {result.api_call_count}")
        print(f"Frameworks:        {', '.join(sorted(frameworks))}")
        print(f"Findings:          {len(result.findings)} total")
        print(f"  Pass: {passed}  |  Fail: {failed}  |  Manual: {manual}")
        print(f"\nArchive: {archive}")
