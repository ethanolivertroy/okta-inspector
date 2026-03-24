"""Abstract base class for framework analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from okta_inspector.models import ComplianceFinding, OktaData


class FrameworkAnalyzer(ABC):
    """Base class every compliance framework analyzer must subclass."""

    name: str  # short identifier, e.g. "stig"
    display_name: str  # human-readable, e.g. "DISA STIG"

    @abstractmethod
    def analyze(self, data: OktaData) -> list[ComplianceFinding]:
        """Run all checks for this framework and return findings."""
        ...
