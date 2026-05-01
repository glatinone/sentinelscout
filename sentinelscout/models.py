"""IOC data models."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Source(Enum):
    VIRUSTOTAL = "virustotal"
    ALIENVAULT = "alienvault"
    SHODAN = "shodan"
    CVE = "cve"
    GITHUB_ADV = "github_adv"
    UNKNOWN = "unknown"


@dataclass
class IOCResult:
    source: Source
    indicator: str
    found: bool
    severity: Severity = Severity.UNKNOWN
    confidence: float = 0.0  # 0.0 - 1.0
    summary: str = ""
    raw_data: dict = field(default_factory=dict)

    def score(self) -> int:
        """Return 0-100 threat score."""
        sev_map = {
            Severity.UNKNOWN: 0,
            Severity.LOW: 20,
            Severity.MEDIUM: 45,
            Severity.HIGH: 70,
            Severity.CRITICAL: 95,
        }
        return min(100, int(sev_map[self.severity] * self.confidence))


@dataclass
class AnalysisReport:
    indicator: str
    sources: list[IOCResult]
    ai_summary: str = ""
    threat_score: int = 0

    def source_summary(self) -> str:
        lines = []
        for r in self.sources:
            icon = {"unknown": "⚪", "low": "🟢", "medium": "🟡", "high": "🔴", "critical": "🚨"}[r.severity.value]
            lines.append(f"{icon} {r.source.value.upper():16s} [{r.severity.value.upper()}]")
            if r.summary:
                for line in r.summary.split("\n"):
                    lines.append(f"   └─ {line}")
        return "\n".join(lines)