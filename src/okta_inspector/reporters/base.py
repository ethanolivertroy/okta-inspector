"""Abstract base class for report generators."""

from __future__ import annotations

from abc import ABC, abstractmethod

from okta_inspector.models import ComplianceFinding, OktaData
from okta_inspector.output import OutputManager


class ReportGenerator(ABC):
    """Base class every report generator must subclass."""

    name: str  # identifier, e.g. "executive"
    display_name: str  # human-readable

    @abstractmethod
    def generate(
        self,
        findings: list[ComplianceFinding],
        data: OktaData,
        output: OutputManager,
    ) -> None:
        """Generate report files via *output*."""
        ...
