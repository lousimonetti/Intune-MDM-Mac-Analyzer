"""Core data models shared across collectors, parsers, the analyzer and reports.

Everything here is plain ``dataclass`` based so the whole pipeline can be
serialised to JSON (for the ``--format json`` output and for the test-suite)
without any third-party dependency.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Severity of a :class:`Finding`. Ordered low -> high for sorting."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                 Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


class Level(str, Enum):
    """Normalised log line severity."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    UNKNOWN = "unknown"


class Source(str, Enum):
    """The Microsoft/macOS subsystem a log line came from."""

    INTUNE = "Intune MDM Agent"
    PSSO = "Platform SSO"
    INSTALL = "macOS App Install"
    DEFENDER = "Microsoft Defender"
    AUTOUPDATE = "Microsoft AutoUpdate"
    OFFICE = "Microsoft Office"
    SYSTEM = "macOS System / MDM"


@dataclass
class LogEntry:
    """A single normalised log line."""

    source: Source
    level: Level
    message: str
    timestamp: Optional[_dt.datetime] = None
    component: str = ""
    file: str = ""
    line_no: int = 0
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["level"] = self.level.value
        d["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return d


@dataclass
class Finding:
    """An actionable observation produced by the analyzer."""

    id: str
    severity: Severity
    source: Source
    title: str
    description: str
    recommendation: str
    category: str = "General"
    count: int = 1
    evidence: list[str] = field(default_factory=list)
    docs_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["source"] = self.source.value
        return d


@dataclass
class SourceSummary:
    """Per-source roll-up of what was parsed."""

    source: Source
    files: list[str] = field(default_factory=list)
    lines_parsed: int = 0
    counts: dict[str, int] = field(default_factory=dict)  # Level.value -> n
    first_seen: Optional[_dt.datetime] = None
    last_seen: Optional[_dt.datetime] = None

    @property
    def errors(self) -> int:
        return self.counts.get(Level.ERROR.value, 0)

    @property
    def warnings(self) -> int:
        return self.counts.get(Level.WARNING.value, 0)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["source"] = self.source.value
        d["first_seen"] = self.first_seen.isoformat() if self.first_seen else None
        d["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return d


@dataclass
class CISCheckResult:
    """Result of evaluating a single CIS Level 1 control against the logs."""

    id: str
    title: str
    section: str
    status: str  # "pass" | "fail" | "not-assessed"
    rationale: str
    remediation: str
    evidence: list[str] = field(default_factory=list)
    docs_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CISReport:
    """A CIS Level 1 validation roll-up with a match-score KPI.

    The score is the share of *assessable* controls that pass; controls we
    cannot judge from the collected logs are reported separately so the KPI is
    not diluted by missing telemetry. Thresholds (per requirement):
    ``>= 95`` green, ``75-95`` yellow, ``< 75`` red.
    """

    checks: list[CISCheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == "fail")

    @property
    def not_assessed(self) -> int:
        return sum(1 for c in self.checks if c.status == "not-assessed")

    @property
    def assessed(self) -> int:
        return self.passed + self.failed

    @property
    def total(self) -> int:
        return len(self.checks)

    def score(self) -> int:
        """Match score 0-100: passing share of assessable controls."""
        if self.assessed == 0:
            return 0
        return round(self.passed / self.assessed * 100)

    def status(self) -> str:
        """KPI band: ``green`` >= 95, ``yellow`` 75-95, ``red`` otherwise."""
        if self.assessed == 0:
            return "red"
        score = self.score()
        if score >= 95:
            return "green"
        if score >= 75:
            return "yellow"
        return "red"

    def status_label(self) -> str:
        return {"green": "Pass", "yellow": "Partial", "red": "Fail"}[self.status()]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score(),
            "status": self.status(),
            "status_label": self.status_label(),
            "passed": self.passed,
            "failed": self.failed,
            "not_assessed": self.not_assessed,
            "assessed": self.assessed,
            "total": self.total,
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class AnalysisResult:
    """The full result of an analysis run; the report's only input."""

    generated_at: _dt.datetime = field(default_factory=_dt.datetime.now)
    hostname: str = ""
    device_info: dict[str, str] = field(default_factory=dict)
    input_path: str = ""
    summaries: list[SourceSummary] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    entries: list[LogEntry] = field(default_factory=list)
    cis: Optional["CISReport"] = None

    # ------------------------------------------------------------------ #
    # Derived metrics
    # ------------------------------------------------------------------ #
    @property
    def total_files(self) -> int:
        return sum(len(s.files) for s in self.summaries)

    @property
    def total_lines(self) -> int:
        return sum(s.lines_parsed for s in self.summaries)

    @property
    def total_errors(self) -> int:
        return sum(s.errors for s in self.summaries)

    @property
    def total_warnings(self) -> int:
        return sum(s.warnings for s in self.summaries)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        out: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def health_score(self) -> int:
        """A 0-100 health score. 100 == clean, penalised by findings.

        Weighting roughly mirrors operational impact; the score is clamped
        to the 0-100 range so the report can render it as a gauge.
        """
        weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 12,
            Severity.MEDIUM: 5,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }
        penalty = sum(weights[f.severity] for f in self.findings)
        return max(0, min(100, 100 - penalty))

    def health_grade(self) -> str:
        score = self.health_score()
        if score >= 90:
            return "Healthy"
        if score >= 75:
            return "Good"
        if score >= 50:
            return "Needs Attention"
        if score >= 25:
            return "At Risk"
        return "Critical"

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "hostname": self.hostname,
            "device_info": self.device_info,
            "input_path": self.input_path,
            "health_score": self.health_score(),
            "health_grade": self.health_grade(),
            "totals": {
                "files": self.total_files,
                "lines": self.total_lines,
                "errors": self.total_errors,
                "warnings": self.total_warnings,
            },
            "severity_counts": self.severity_counts(),
            "cis": self.cis.to_dict() if self.cis else None,
            "summaries": [s.to_dict() for s in self.summaries],
            "findings": [f.to_dict() for f in self.findings],
        }
